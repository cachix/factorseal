# Memory hardening

FactorSeal keeps installation roots, derived index keys, operational signing
seeds, document encryption keys, password-derived wrapping keys, and archive
keys in dedicated locked allocations. Retained CLI passwords, Desktop secret
editor text and worker passwords, `WireSecret` values, store-worker value
responses, archive payloads, and native/worker IPC frame buffers also use locked
storage. A nonempty allocation owns writable OS pages between inaccessible
guards; its bytes end immediately before the trailing guard. The address stays
stable when its Rust owner moves. Empty byte buffers allocate no pages.
`LockedKey` and `LockedBytes` have no implicit Clone or serialization. All
writable pages, including padding, are zeroized before unlocking and releasing
the reservation.

Request/response and worker-bootstrap serialization count against the existing
size bound, then write directly into an exactly sized locked buffer. Base64
encoding/decoding of `WireSecret` uses locked storage and preserves the existing
wire format. Transferring a `WireSecret` into/out of `LockedBytes` moves ownership
without copying. `WireSecret::new` now returns `VaultResult`; request/response
`encode` now returns `LockedBytes`. This is a Rust API change, not a protocol or
archive format change.

Desktop edits allocate locked storage before accepting replacement text. A lock
failure preserves the previous edit, displays an error, and returns an empty
submission until a successful edit or clear; it never falls back to pageable
editor storage.

New roots and signing seeds are generated directly in locked storage. Argon2
and PBKDF2 write their derived key outputs there. Hardware and AEAD decoding
still return temporary zeroizing buffers; their fixed-size keys are copied
into locked storage and those temporary buffers are dropped. The backend root
payload is dropped immediately after decoding, before opening the key hierarchy.

## Platform enforcement

| Platform | Secret allocation | Crash reporting |
| --- | --- | --- |
| Linux | `mmap`, inaccessible guard pages, `mlock`, `MADV_DONTDUMP`, `MADV_WIPEONFORK` | Existing Unix core-file suppression and nondumpable key-owner processes remain. Protected pages are excluded from core dumps and zero-filled in a fork child. |
| macOS and other Unix targets | `mmap`, inaccessible guard pages, `mlock` | Existing Unix core-file suppression remains. This implementation does not claim Linux's per-mapping fork or dump controls on these targets. |
| Windows | `VirtualAlloc` reservation with uncommitted guards; committed middle region protected by `VirtualLock` | Request WER `NOHEAP`, preserving existing WER flags. Failure to set/query the policy is an error. This does not override LocalDumps or prevent external/privileged dump tools. |
| Other targets | Unsupported | Secret allocation returns an error. There is no silent pageable fallback. |

Lock/protection failures propagate as vault protection errors. Embedders receive
the same allocation requirement; product entry points separately configure
process crash protections. Memory lock limits must accommodate all concurrently live protected buffers. Each key consumes one locked page (typically 4 KiB on Linux,
but query the host's actual page size). An open vault retains two such pages;
creation, signing, document operations, export and concurrent vaults require
additional pages. Each nonempty value/editor/frame buffer consumes its size
rounded up to an OS page, even for a one-byte value. Edits temporarily retain
old and new buffers; serialized/base64 buffers coexist with the source values.
Bulk archives retain many values and a serialized payload simultaneously: a
large archive can exceed a typical 8 MiB Unix lock limit well below the archive
file-size bound. Size bounds are not promises that the host lock quota can
support that workload. Guard reservations also consume virtual address space.
Linux requires support
for `MADV_WIPEONFORK` (kernel 4.14 or newer).

On Unix inspect `ulimit -l` or the service's `LimitMEMLOCK`. If a legitimate
operation fails to lock memory, adjust the deployment's limit based on its
workload; do not disable locking. Test harnesses on hosts with small limits can
use `--test-threads=1` to avoid multiplying vaults across concurrent tests.
Windows has a working-set-derived lock quota; the application does not expand
that quota automatically.

## Limits

This protects the listed owned allocations, not all plaintext in the process.
Terminal/file/askpass reads, Desktop submission snapshots, clipboard/input-method
buffers, Secret Service session internals, provider-returned strings,
hardware/AEAD intermediates, JSON parser scratch (including escaped strings),
Automerge documents and serialized snapshots, Argon2 scratch memory, and
cryptographic-library expanded keys or stack/register copies are not all locked.
Zeroizing temporary inputs are wiped when converted to locked storage, including
on allocation failure. Caller-owned source slices remain the caller's responsibility. Existing zeroization is not a guarantee that every temporary copy is
wiped. Guard pages catch crossing the writable region boundary; they do not detect
all intra-page underflows. Locked pages are not encrypted RAM and do not prevent
privileged inspection, same-process compromise, hibernation images, or physical
memory attacks. Process entry points must still apply crash protections before
accepting secrets.

Native platform evidence and independent review remain release requirements
documented in `security-release-gates.md`, independent of issue #3's closure.
This change does not claim comprehensive memory erasure or complete dump prevention.

## Verification

- Stable and distinct key/variable-length allocations, redacted Debug, zero
  initialization, invalid sizes, and full-region wiping including page padding.
- Empty and multi-page buffers, exact serialization bounds, compatible base64
  round trips, malformed encoding rejection, and ownership transfer without copies.
- Desktop UTF-8 edits at the size limit, clear, and simulated allocation failure
  with recovery.
- Linux `/proc/self/smaps` verifies locked, dump-excluded and wipe-on-fork flags;
  dropping one key leaves another key's separate mapping locked.
- Isolated Unix children deliberately hit both guard pages with core files
  disabled. A child with a zero memory-lock limit must fail allocation.
- A Linux fork child sees zeroed key bytes; the parent retains its original key.
- Windows tests inspect reserved/committed page protections and query WER flags.
  These require native Windows execution to establish runtime behavior.
- Existing crypto vectors and vault create/unseal/storage/archive regressions
  check that protected storage preserves cryptographic and lifecycle behavior.

API references: [Linux madvise](https://www.man7.org/linux/man-pages/man2/madvise.2.html),
[Windows VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock),
[Windows WER flags](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-wersetflags).

# Offline integrity and rollback profile

This profile authenticates content and detects inconsistent/partial rollback.
It deliberately excludes rollback of an entire vault directory while the owner
is stopped. Restoring all metadata, database, sidecars and the signed head from
one older consistent copy can restore older values and grants. Hardware binding
does not establish freshness. Backups and filesystem snapshots are not trusted
checkpoints. This exclusion satisfies issue #3's explicit-profile alternative;
it is not a claim that whole-directory rollback was implemented.

During a lease, verified document heads and the global head remain in memory.
Reads, mutation preconditions and compaction compare against this state. A
signature, digest, missing-document, chain-cycle or incompatible-state failure
seals the store rather than signing over it. On restart, the complete stored
chain and inventory are verified. Crash consistency still depends on Turso's
transaction/WAL implementation: integrity checking detects inconsistency but
does not repair it. Keep a separately encrypted portable export for recovery.

The storage profile assumes trusted ancestor directories and a single vault
owner. Root ownership/private permissions are checked, and metadata, password
and lock handles reject final symlinks/reparse points, hard links and non-regular
files. Export replacement uses a private temporary file, file synchronization,
atomic rename and Unix parent-directory synchronization. Database/sidecar opens
remain implemented by Turso; arbitrary concurrent ancestor replacement by the
same user and hostile privileged filesystem mutation are outside this profile.
Deletion and `destroy` are logical removal, not media erasure or revocation of
retained hardware-bound backups.

A future rollback-detecting profile needs a trusted monotonic witness outside
the directory. It must bind the installation identity, commit digest and
monotonic counter, with authenticated reads and compare-and-swap advancement.
The protocol must define recovery for crashes between local commit and witness
advancement, reject unavailable witnesses instead of downgrading, preserve a
newer witness across reinstall/restore, and provide explicit administrative
recovery when hardware or the witness is lost. A plain file or unrestricted
keyring entry outside the directory does not meet those requirements. This is
a separate format/deployment decision; no hidden checkpoint is created here.

Request IDs are a bounded 4,096-entry duplicate window over authenticated local
transport. They are not an indefinitely retained anti-replay ledger. Eviction
and process restart permit reuse; authorization and current lease/grant checks
still apply to every request. Tests intentionally retain this boundary.

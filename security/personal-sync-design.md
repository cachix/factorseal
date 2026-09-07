# Personal vault replication design

Status: proposed architecture, 2026-09-07. No runtime behavior is implemented by
this document. This supersedes the proposal to require unlocked vaults for all
sync. Wire formats and key distribution require a separate protocol review.

Implementation progress: the core personal model, ID-based storage, transactional
legacy migration, and local causal revision/publication journal are implemented.
The existing reserved namespace is enforced in the core storage boundary; it
remains a LocalKeyring document with a personal format version. Current item
values and pending revision references share one signed encrypted generation.
This local journal has single-parent writer chains. The experimental
`personal-sync` feature now provides signed portable envelopes, per-reader
content-key wrapping, and a separate durable ciphertext spool. See the
[implemented packet boundary](personal-sync-wire.md). These primitives are not
connected to the vault worker yet. Persistent reader identities, authenticated
membership enrollment, the multi-parent conflict model, spool handoff,
acknowledgements, and network replication below remain to be implemented.

## Product contract

Personal secrets are a replicated collection. Every trusted reader device keeps
an independently hardware-protected local vault. Devices can exchange durable
encrypted updates while locked; decryption, local application, editing, and
membership changes require unlocking. Offline edits are durable and catch up
later. Direct replication is symmetric and has no primary data server.

A storage-only node can retain and forward ciphertext without being a vault
reader. This is the role for a future home server or cloud mailbox. A locked
phone can perform the same forwarding when its operating system runs the app.
No phone is required to remain unsealed.

Only personal item content, its revisions, and the group state needed to manage
replication participate. Hardware keys, installation roots, unlock factors,
application grants, project credentials, Secret Service data, provider caches,
and local access history never enter the replication stream. A manually saved
SSH/API credential in Personal secrets is personal content; scope follows the
collection, not the credential's type.

## Constraints found in the current code

- `factorseal-desktop/src/runtime.rs` defines the personal namespace and stores
  items through generic `Put` using the title as the address. Imports use generic
  archive entry operations. All these mutation paths need a shared core boundary.
- `src/transfer/personal.rs` already gives structured items a UUID. Move the
  model into a core personal module and retain compatibility re-exports for
  transfer callers. Transfer formats must not own the storage domain model.
- `src/vault/envelope.rs` binds snapshots to local vault/document/device IDs.
  Their DEKs are wrapped by installation authority. Copying snapshots does not
  make another installation able to decrypt them.
- `src/vault/document.rs` deliberately persists fresh projections of current
  records. Its Automerge operation history is not a reusable replication log.
- `src/vault/store/worker/mutation.rs` commits protected local generations in
  one transaction. Preserve this crash-consistency boundary.
- `src/bin/factorseal/desktop_worker.rs` and Desktop's lifeline terminate the
  key owner on seal. The main database must remain owned solely by that worker.

## Process and storage boundaries

```text
Desktop / CLI
    | authorized personal operations
    v
Vault worker (only while unlocked)
    local vault DB + protected sync keys + applied frontier + durable outbox
    | bounded native IPC: immutable ciphertext, membership, acknowledgements
    v
Sync agent (can run while locked)
    separate ciphertext spool + public membership + transport credentials
    | versioned replication protocol
    +---- iroh peer
    +---- storage-only node
    +---- future cloud object-store adapter
```

The sync agent is a separate process and owns a separate database. It never
opens the vault database and has no generic vault read/export grant. Its API
accepts bounded ciphertext objects and returns candidates for worker validation.
The worker treats it as untrusted input, including its claimed membership and
delivery status. Compromise can disrupt delivery and expose traffic metadata;
it must not grant plaintext access or authority to author secret changes.

Desktop sealing/exit still tears down the key owner. A user-session service can
keep the sync agent alive after Desktop exits. Disabling sync stops networking;
sealing stops secret access. Mobile hosts embed the same replication core under
OS scheduling instead of promising a permanent daemon.

## Key hierarchy and encrypted records

Separate three roles:

1. **Transport identity:** available to the locked agent for connections and
   storage authentication. It cannot sign personal edits or unwrap secrets.
2. **Reader/writer identity:** content signing and recipient decryption keys,
   root-wrapped locally and usable only inside an unlocked worker. Use distinct
   keys and domains from the installation commit key.
3. **Group membership authority:** approves readers, storage endpoints, and
   membership epochs. Its private authority is also protected by an unlock.

Start with per-record envelope encryption, avoiding a long-lived shared content
key. Each revision gets a fresh random AES-256-GCM DEK. Wrap that DEK separately
to each reader's public encryption key in the named membership epoch. Small
personal device groups make the per-recipient overhead reasonable. Devices
receive the exact same immutable object through any transport.

The signed envelope binds protocol version, random group ID, membership digest,
author identity, unique operation ID, recipient key packages, nonce, and
ciphertext. Define a canonical encoding and domain-separated signatures. Hash
the signed ciphertext object for its transport ID; never publish plaintext
hashes. Keep item IDs, names, values, item-parent revisions, edit timestamps,
and operation kind inside encryption. Public membership and object sizes/counts
still reveal group relationships and traffic volume; names are encrypted.

Use an established recipient-encryption construction, not a custom asymmetric
scheme. HPKE is a candidate, but the exact library, suite, and post-quantum/FIPS
policy remain an implementation gate: existing ML-DSA signatures do not make
classical key encapsulation or iroh transport post-quantum. Authenticate every
key package through the content signature and membership binding. Do not
silently change the project's cryptographic claims.

The agent can verify signatures and known membership without a DEK, but cannot
validate encrypted item semantics. Unknown epochs are bounded pending input.
The worker independently verifies the full membership chain, signature, AEAD,
schema, scope, revision dependencies, and replay state before application.

## Personal data and conflict model

Introduce typed personal CRUD/list/import operations and a dedicated personal
storage scope. Migrate the existing namespace transactionally on unlock. Preserve
valid IDs; detect duplicate IDs and retain ambiguous legacy/imported records
with explicit mappings rather than silently coalescing them. Titles become
editable display metadata. Two different items may share a title.

Each edit is a complete item revision with an ID and its known parent revisions.
Use an item-level multi-value register: a causally later revision supersedes its
parents; concurrent revisions remain visible conflicts. V1 does not merge
password fields independently or choose a winner by wall-clock time. Resolving
a conflict writes a revision naming all conflicting heads as parents.

A delete is a revision with a tombstone. Concurrent edit/delete is a conflict,
not an automatic resurrection or silent data loss. Unrelated item edits commute.
Imports, generic legacy writes, clears, and any supported expiry must route
through these rules or be rejected for personal scope. Remote apply must not
emit a second local edit and cause replication loops.

Existing local history remains value-free. New encrypted revision payloads are
temporary delivery/conflict state, not an unlimited password-history feature.

## Crash-safe publishing and applying

On a local edit, the worker creates the signed encrypted object and commits the
local item, revision metadata, and durable outbox together in the vault database.
Bind outbox object digests and applied frontier into protected local state;
unauthenticated SQL bookkeeping cannot become sync authority.

After commit, copy the object to the agent. Only acknowledge spool receipt after
durable storage. A crash anywhere in this handoff causes an idempotent retry.
Keep a worker-side retained copy until replication retention policy permits its
removal; a spool receipt alone is not proof that another device has the update.

On receive, the agent durably stores and forwards the object while locked. On
unlock, the worker validates it, waits for missing dependencies where necessary,
and atomically commits the item/conflict/tombstone plus applied revision state.
Only then issue an application acknowledgement signed by the protected writer
identity. Replays and reordered deliveries have no additional effect.

Use separate receipts for durable ciphertext possession and validated application.
Neither an untrusted cloud acknowledgement nor a transport-key signature proves
that a reader decrypted/applied a revision. Seal during an operation either
leaves a committed result or retries from durable state after unlocking.

## Transport contract and three devices

Implement bounded, paginated inventory exchange, missing-object requests,
immutable put/get, membership exchange, resumable transfer, and acknowledgements.
An initial simple manifest of ciphertext object IDs is sufficient; transport
ordering is never causal ordering. Bound object size, pending dependencies,
per-peer concurrency, bytes on disk, and request time. Quota exhaustion reports
pending sync instead of deleting unacknowledged edits or claiming success.

The replication state machine is independent of iroh. Give the iroh adapter a
versioned ALPN and authorize group access independently of endpoint identity.
Storage credentials permit ciphertext transfer only. A future storage adapter
must tolerate stale listings, duplicate uploads, omissions, and corrupted data.

Example: A edits offline, reconnects, and sends to locked B. A disconnects.
B later forwards to locked C. C unlocks and applies. B never needed plaintext.
If none of the devices overlap online, a persistent storage node is required.
An ordinary iroh relay only forwards live traffic and stores no mailbox.

## Pairing, membership, and removal

QR pairing authenticates the inviter endpoint and a random single-use invitation
with expiry. Also offer paste/import for desktops without cameras. Bind both
devices' reader keys and the group/membership digest into the pairing transcript;
show a matching verification code and require explicit approval before enrollment.
Pairing and initial personal-item merge require unlocked workers on both sides.

For v1, recommend one explicitly designated membership controller, initially the
first device. Only membership changes require this device to be available and
unlocked; ordinary edits and replication remain fully peer-to-peer. A signed
linear membership chain avoids inventing concurrent administrative consensus.
An invitation can be initiated elsewhere but needs controller approval to finish.
This deliberately narrows the earlier suggestion that any device could finish
pairing independently. Controller transfer is signed by the old controller and
accepted by the new one. Conflicting membership successors freeze administration
and raise an error; never select one by arrival time.

Without the controller, existing devices still sync. If it is permanently lost,
an unlocked surviving reader can explicitly create a replacement group from its
current state and re-pair devices; it cannot impersonate the old controller.
More available membership administration can be a later protocol decision.

Joining devices receive a fresh encrypted checkpoint of current items, conflicts,
and causal/deletion state, encrypted to the new recipient set. They do not need
every historical DEK. Preview pre-existing personal items and merge by identity
with conflicts; never overwrite by matching title alone.

Removal advances the membership epoch, removes the recipient from future key
packages, and revokes storage/transport authorization as appropriate. The epoch
transition names the accepted old-epoch frontier. Do not trust claimed creation
timestamps to decide whether a removed device authored an edit before removal.

Late old-epoch edits beyond that frontier are quarantined. An authorized remaining
device may review and reissue its own unsynced work under the new epoch after
unlock, preserving provenance. Locked agents that learn the transition stop
publishing excluded old-epoch objects. Offline devices unaware of removal may
still encrypt to the old recipient set: revocation takes effect as membership
knowledge propagates, never retroactively. Already copied secrets cannot be
withdrawn. No forward-secrecy or cryptographic-erasure promise for archived
ciphertext and retained recipient keys.

## Retention, restore, and unavailable peers

Keep unresolved conflict payloads and unacknowledged revisions. Compact resolved
payloads only behind a signed checkpoint with coverage acknowledged as applied
by all active readers. The checkpoint retains current heads, deletion/causal
summaries, and enough authenticated state to reject old operations. A locked
storage node cannot create or semantically approve it.

A long-offline active device can delay compaction. Surface storage use and allow
explicit removal of a stale device; do not expire membership silently. Rejoining
after removal starts from a current checkpoint. Best-effort deletion from a cloud
store cannot erase provider backups or another member's copies.

Backups remain separate. Ordinary archive restore imports content as new local
work; it must not restore a live writer identity/frontier and accidentally fork
it. Losing all reader keys leaves encrypted storage unreadable. Recovery key
escrow is a separate product feature, not implicit in sync. A restored whole
directory must reconcile with retained peer checkpoints before publishing; full
rollback with no surviving external checkpoint remains undetectable, consistent
with the current offline integrity limitation.

## User-visible status

Place `Devices · 3` next to Personal secrets, with “3 paired devices, including
this device.” List storage-only endpoints separately so a cloud mailbox is not
counted as a reader device. Keep paired count separate from connectivity.

Track local publication, peer ciphertext possession, and peer application:
`Changes pending`, `Transferring`, `Encrypted changes received`, `Waiting for
unlock`, `Applied`, `Conflict`, and actionable errors. Application status is
relative to a specified acknowledged frontier, not a claim about unseen offline
edits. Offline/locked status is last-known information; avoid false live claims.
Device names are available while unlocked; use generic labels while locked if
showing names would require a plaintext cache.

## Delivery sequence and acceptance

1. Move personal model/scope into core, add ID-based operations, and migrate
   existing records. Test rename, duplicate IDs/titles, and every import/write
   path. Preserve local-only operation when sync is disabled.
2. Specify canonical envelopes, recipient-encryption suite, membership chain,
   frontiers, checkpoint rules, and bounds. Review the crypto/profile changes
   before treating the wire protocol as stable.
3. Implement the revision engine and protected atomic outbox/apply path. Test
   convergence under permutations, conflicts, delete/edit, replay, and crashes.
4. Implement the ciphertext agent and storage contract using a local persistent
   test node, then iroh. Prove locked B can durably carry A's update to C after
   A disconnects. Kill/restart at every handoff and test disk-full behavior.
5. Add QR pairing, controller transfer, removal, and Devices UI. Exercise stale
   memberships, forked chains, old-epoch edits, and expired/replayed invitations.
6. Test sealing during transfer/apply and that agent IPC cannot access other
   namespaces or decryption/signing keys. Fuzz all network/envelope parsers.
7. Add a persistent storage-only deployment using the same contract. A cloud
   adapter and mobile scheduling follow without changing item encryption.

Native background execution and three-device acceptance are release checks.
Documentation must update the current sole-store claim, retention behavior,
metadata exposure, and crypto profile when implementation lands.

## External references

- [Iroh protocols](https://docs.iroh.computer/concepts/protocols): transport and
  application protocols are separate.
- [Iroh FAQ](https://docs.iroh.computer/about/faq): relays route encrypted packets
  and are stateless; they do not supply persistent delivery.
- [HPKE, RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html): candidate
  recipient encryption; application replay/order and key policy remain ours.
- [Apple background strategies](https://developer.apple.com/documentation/backgroundtasks/choosing-background-strategies-for-your-app):
  the system schedules background work.
- [Android Doze and App Standby](https://developer.android.com/training/monitoring-device-state/doze-standby):
  idle/background network access is restricted. A phone is an opportunistic
  courier, not guaranteed always-on infrastructure.

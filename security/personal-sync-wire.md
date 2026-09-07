# Experimental personal sync boundary

Implemented behind the optional `personal-sync` feature. This connects the vault
worker and ciphertext storage through trusted host-management APIs; it does not
start networking or expose sync operations through application IPC.

## Automerge and personal scope

Each stable personal item ID owns a separate Automerge document. Its root
`value` is either the current encoded personal item or a null tombstone. An item
is an atomic register: concurrent password edits must not silently mix fields.
Automerge owns operation IDs, dependency tracking, head hashes, merge behavior,
and conflict resolution. The old custom revision journal is read only during
migration, to recover its final tombstones.

`PersonalUpdate` carries an item ID and the complete set of native uncompressed
Automerge changes for that item, encoded as base64 byte strings in JSON. Full
closures make packets independently useful to a late reader through an offline
courier. This is Automerge change replication, not its interactive per-peer
sync-message protocol. Missing dependencies, duplicate changes, unsupported
operations, and item-ID mismatches are rejected. Validation checks every
historical operation, including superseded ones: exactly one root `value`
assignment per change, containing a valid personal item or null. Other root
properties, objects, messages, and extra change payloads are rejected. Automerge
may encode choosing the current winner by deleting its losing operations. Such
native resolutions are accepted only when the causal pre-state has multiple
values and the post-state retains exactly one of them. Deletion of the entire
register is rejected, including when disguised by a later write. Uncompressed change chunk type 1 is required before parsing; network
inputs cannot invoke document/chunk decompression.

Distinct concurrent values are retrieved using Automerge `get_all`, never its
single-value default winner. Ordinary item reads and writes return a conflict.
The host can display every candidate, including deletion, and explicitly choose
one. Resolution compares the complete observed head set before assigning a new
value. If a third edit arrived, the stale decision fails. A later Automerge
change supersedes its dependencies; delayed ancestors cannot resurrect an item.

The outer installation document still projects current records on each commit.
It now carries a separate encrypted replica catalog intact across projection.
Local keys, membership, audit metadata, publication state and receipts stay
outside those replica documents and never enter an outgoing update.

**Retained history includes old and deleted passwords.** Newly enrolled readers
currently receive that history too. Automerge snapshot compaction does not erase
it. There is no history-pruning or cryptographic-erasure claim. A future bounded
rebootstrap/checkpoint protocol must account for offline peers and stale changes
before any such pruning can be implemented.

## Keys, membership and packet encryption

Reader identities use independent ML-KEM-768 and ML-DSA-65 seeds, root-wrapped
with separate purpose labels bound to the local installation and vault IDs.
Only wrapped seeds are persisted inside the authenticated encrypted local
snapshot. Unwrapped seeds and fresh content keys use locked guarded allocations
for each operation. Cryptographic library intermediates and Automerge's plaintext
working memory are not all page-locked or explicitly wiped; transient owned
serialization buffers are zeroized where supported.

The trusted host must authenticate enrollment before calling
`configure_personal_sync`. Public-key validation is not membership authority.
The persisted membership requires this device's reader key, a stable group ID,
and monotonically increasing epochs. Changing the membership clears an obsolete
prepared packet and marks all current replica histories for republication.
Controller signatures and QR enrollment are still pending. A transport identity
is not a reader identity.

The versioned suite is
`automerge-mlkem768-hkdfsha256-aes256gcm-mldsa65-v1`. Previous experimental custom
revision packets are rejected. Each packet:

1. Encrypts the update with a fresh random AES-256-GCM content key and nonce.
2. Binds suite, group, epoch, membership digest, author, random operation ID and
   exact sorted recipient list as payload associated data.
3. Wraps that key independently to every reader using ML-KEM-768 HPKE Base mode,
   HKDF-SHA256 and AES-256-GCM. The wrap binds the payload context, recipient,
   nonce and ciphertext digest under a separate domain.
4. Signs the complete envelope body under a separate ML-DSA-65 domain.
5. Uses SHA-256 of the full encoded ciphertext packet as its storage address.

The implementation pins `hpke` 0.14.1. Its ML-KEM construction follows
[draft-ietf-hpke-pq-04](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04),
an extension to [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).
The construction remains experimental and requires protocol review; this is not
a FIPS module-validation claim.

Outer encoding is compact JSON in struct field order, with base64 byte vectors
and JSON arrays for fixed-size identifiers. Public verification requires exact
re-encoding equality, expected membership and recipient set, and a valid author
signature. It needs no reader keys. Opening rechecks membership before decrypting
and validating the Automerge payload. A signature alone does not prove valid
changes or application. Members can edit personal content; signatures identify
the packet issuer, not independent authorization for each historical change.

Storage nodes see group, epoch, author/member fingerprints, recipients, packet
lengths and traffic patterns. Item IDs, change hashes, values and history remain
inside encryption. No padding or metadata-hiding transport is implemented.
Revocation cannot withdraw old plaintext, ciphertext or keys already received.

## Transactional publication and application

Local edits commit current records, Automerge history and pending item IDs in
one signed encrypted transaction. Preparing a publication commits exact packet
bytes plus their item ID and Automerge heads in that same local document before
returning them to the host. The host writes and synchronizes the ciphertext spool
before confirming possession to the worker. Only a matching prepared packet ID
is accepted. The pending marker clears only if the item's current Automerge
heads still equal the prepared heads. An intervening edit remains pending.
Retries reuse the identical prepared bytes across restart; crashes before or
after spool publication cannot lose a newer edit.

Received packets are publicly verified and decrypted inside the lease-bound
worker. Automerge merges their changes. Materialized records, the complete
merged replica and receipt are committed together. Duplicate packet receipts
are idempotent; re-encrypted or reordered Automerge changes are also idempotent.
Concurrent candidates remain in Automerge, not a parallel conflict-value table.

`publish_personal_sync` and `apply_personal_sync` process bounded spool batches.
After unlock the host can restart inventory from the beginning and replay safely.
Stored ciphertext inventory is separate from the vault's counts of incorporated
received packets and packets whose current values still conflict. Enrolled
reader count is not a claim that all readers are online or up to date. These are
local durable receipts; authenticated peer application acknowledgements remain
future work. Sync activity does not refresh the unseal lease. Sealing drops the
worker and its unwrapped keys while the independent ciphertext store can remain.

The spool uses an owner-private directory, exclusive process lock, immutable
content addresses, private atomic file publication, file synchronization and
Unix parent-directory synchronization. Retries reverify and synchronize the
existing object. Reads reverify both membership/signature and filename hash.
A stale-epoch packet remains stored but is rejected by a current-epoch apply pass.
Disk failures abort the pass; malformed packets never seal an otherwise healthy
vault. Native filesystem/lifecycle acceptance is still required on each platform.

Bounds are 16 readers and distinct concurrent values, 4,096 changes per item,
1 MiB encoded update/history, 2 MiB encrypted packet, 4,096 replica items,
32 MiB encoded replica catalog, 16 MiB local sync state, 4,096 received receipts,
4,096 spool objects and at most 128 entries per batch/page. Spool byte quota is
caller-supplied. History/catalog limits reject edits before committing them.
Orphan temporary files consume spool quota but are not advertised. No automatic
eviction, receipt cleanup or history pruning is implemented.

Next integration work is authenticated enrollment/controller updates, background
iroh transport, QR pairing, management UI, peer application acknowledgements,
and reviewed retention/rebootstrap. The architecture is described in
[personal-sync-design.md](personal-sync-design.md).

## Signed groups and optional iroh courier

`VerifiedGroup` verifies an ML-DSA-65 controller-signed certificate chain against
an explicitly trusted controller fingerprint. Genesis starts at epoch 1; each
successor names the preceding certificate hash and retains the controller key.
A pinned chain accepts extensions, never rollbacks or signed forks. Chains are
bounded to 64 epochs and 8 MiB. Controller transfer is not implemented. The host
must persist its pin before activating an update; a verified chain received from
a peer alone does not establish initial trust.

Each current reader has exactly one named iroh endpoint binding. Additional
bindings with no reader identity authorize ciphertext storage/forwarding only.
They add no encryption recipient. At most 16 readers and 32 transport endpoints
are allowed. The worker now persists its controller pin and signed chain in the
local encrypted sync state, together with the matching packet membership. Once
pinned (or joining is pending), the legacy raw `configure_personal_sync` API is
disabled. A membership change invalidates prepared old-epoch ciphertext and
queues all existing personal histories for publication to the new recipients.

`personal-sync-network` adds an iroh 1.1 courier library using ALPN
`factorseal/personal-sync/1`. The embedding host supplies the endpoint and owns
its secret, lifetime, connection limits and address discovery. No listener starts
by default. The courier owns only public authorization and the ciphertext spool;
it accepts neither an unlocked vault nor reader keys. Configure production
endpoint discovery/relays explicitly; tests use iroh's Minimal preset with local
addresses and no public relay/discovery dependency.

The trusted local host can use `with_spool` on a blocking worker to serialize
vault publication/application with network storage. Its callback receives the
current public membership and must not reenter the courier. The courier retains
neither the callback nor any key-owning vault handle.

Each connection serves one bounded inventory/get request. Both the authenticated
iroh peer identity and current signed group digest must match. Packet signatures
are rechecked at read and durable receipt. Inventory pages contain at most 128
packet IDs; frames are limited to 3 MiB, requests to 20 seconds, and one pull page
to one minute. Disk operations use blocking workers outside the async executor.
Hosts should serve serially or impose a session limit; iroh transport-level
resource limits must also be configured by the eventual background host.

Pull is idempotent and restartable by packet-ID cursor. Each device pulls from
its peers independently. A storage-only node can retain a sender's packets and
later forward them when that sender is offline. Inventory includes old epochs;
fetch rejects packets no longer authorized by the current membership. Such
packets still consume spool quota until an explicit future cleanup policy.
Counters report ciphertext possession (including duplicates), never peer vault
application, online-device count, or convergence. A group update is synchronized
with spool operations and invalidates stale requests, but cannot retract bytes
already released before that update.

Pairing network routing, persistent transport credentials, automatic membership
distribution, background process/control IPC, peer application receipts, and the
Devices UI remain integration work. No continuously unlocked
phone is required by the courier, and an iroh relay is not persistent storage.


## Durable pairing management

The lease-bound trusted host API now supports creating a signed group, issuing
an invitation, preparing/staging a joining request, approving that exact request,
accepting its signed response, cancelling pending pairing and restoring pending
status. None of these methods is exposed through application IPC. Only the
controller issues invitations and approves new readers. The worker never exports
reader seeds. Both pairing devices must be unlocked for their management steps;
subsequent ciphertext forwarding does not require unlocking.

An invitation lasts five minutes and contains a random 256-bit bearer secret,
the controller fingerprint, inviting endpoint, current certificate digest and
expiry. The 136-byte payload has a versioned URL-safe base64 ticket under 256
characters. `personal-sync-network` can render that ticket as an SVG QR. Public
reader keys are fetched separately. Tickets and SVGs are sensitive: owned ticket,
serialization and SVG buffers are wiped on drop where supported; QR library
intermediates and deserializer allocations are not all wiped or page-locked.

The joining worker verifies the offered chain against the scanned controller
and exact certificate digest. It persists a request binding the invitation,
joining endpoint, reader keys and device name, with an HMAC capability proof and
an ML-DSA reader signature. The controller validates that request and binds the
invitation to the first valid staged request. A different request is rejected
until cancellation or invitation expiry. The transport host must pass iroh's
authenticated endpoint ID into staging; a claimed endpoint from wire data is not
sufficient.

Both devices display the same 12-hex-digit verification code (48 bits) derived
from the complete request. The host must obtain explicit user approval after
comparison, then pass the full 32-byte request ID to approval. Staging alone
changes no membership. Approval checks expiry, consumes the invitation and commits
a signed successor containing the request digest before returning it. Retrying
that approval after a restart returns the committed chain. The joining device
requires its persisted invitation anchor, an extension containing its approved
request digest, and its own current reader/endpoint binding before accepting.
A delayed approved response remains acceptable after invitation expiry; expiry
limits approval, not delivery of an already committed decision.

Pending requests survive restart without generating a new randomized signature
or verification code. Cancellation removes pending authorization. Existing members
accept only extensions of their pinned chain; unknown initial chains, rollback,
forks and unapproved initial responses are rejected. The approval API requires a
trusted host: enforcing the actual user interaction and fetching/sending pairing
messages over iroh are still UI/background-host integration work. The ciphertext
courier itself does not accept unpaired connections or perform enrollment.

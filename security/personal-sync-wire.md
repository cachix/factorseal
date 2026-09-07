# Experimental personal sync packet boundary

Implemented behind the optional `personal-sync` feature, 2026-09-07. This is a
library boundary, not an enabled background sync service. The architecture in
[personal-sync-design.md](personal-sync-design.md) remains the integration plan.
The format requires a separate protocol review before production deployment.

## Content and authority

`PersonalUpdate` contains one current personal item or a deletion marker, plus
its single-parent revision chain. It cannot carry arbitrary vault namespaces,
device unlock factors, or installation roots. All chain entries must have the
same item ID, unique revision IDs, and contiguous ancestry beginning at a root.
The head must agree with the item's ID and presence/deletion. This is validation
of one writer chain; it does not implement conflict resolution or establish
that an author's claimed ancestry is already trusted by a receiver.

Each `ReaderIdentity` has independent ML-KEM-768 and ML-DSA-65 seeds. Retained
seeds and fresh content keys use locked, guarded allocations. Expanded keys and
cryptographic intermediate values are temporary library-owned allocations;
this does not claim all library intermediates are page-locked. Serialized
outgoing plaintext is locked; decrypted bytes are zeroized on release.
Reader identities currently have no persistence API. They are separate from
future iroh transport credentials.

`Membership::new` validates and sorts public keys, rejects duplicates, and binds
them to a group and epoch. **It does not authenticate membership.** Its caller
must supply keys authenticated by the future pairing/controller protocol.
Accepting an arbitrary peer-supplied membership would defeat author and reader
authorization. There is no controller, enrollment, or epoch persistence yet.

## Envelope construction

The versioned suite is `mlkem768-hkdfsha256-aes256gcm-mldsa65-v1`:

1. Generate a fresh 256-bit content key and random operation ID for each packet.
2. Encrypt the personal update with AES-256-GCM and a fresh nonce. Associated
   data binds the suite, group, epoch, membership digest, author, operation ID,
   and exact sorted recipient list.
3. Wrap that content key independently to every current reader, including the
   author, using HPKE Base mode with ML-KEM-768, HKDF-SHA256, and AES-256-GCM.
   Wrap associated data also binds the recipient, payload nonce, and ciphertext
   digest. The HPKE info field uses a separate key-wrap domain.
4. Sign a separate domain plus the entire encoded envelope body with ML-DSA-65.
   The signature covers every recipient package and the encrypted payload.
5. Address the resulting object by SHA-256 of its complete encoded ciphertext
   packet. No plaintext-derived identifier is exposed as a storage address.

The implementation pins `hpke` 0.14.1. Its ML-KEM construction follows
[draft-ietf-hpke-pq-04](https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-04),
an extension to [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).
See the [implementation's KEM documentation](https://docs.rs/hpke/0.14.1/hpke/kem/index.html).
The PQ HPKE construction is draft-based; this format is experimental and makes
no FIPS module-validation claim.

Encoding is compact JSON in the declared Rust struct field order, with standard
base64 for byte vectors and JSON byte arrays for fixed-size identifiers.
Verification requires exact re-encoding equality and rejects unknown fields,
alternate whitespace/field order, unsupported suites, stale epochs, and any
recipient-set mismatch. This is this protocol's canonical encoding, not JCS.
The membership digest hashes a separate domain, group bytes, big-endian epoch,
and the sorted encoded public-key list.

Public verification authenticates a packet against the supplied current
membership without any reader key. Opening rechecks that membership, unwraps
the content key, authenticates/decrypts the payload, and validates its structure.
A valid signature does not imply decryptability, valid revision ancestry, or
successful application. A removed member retains access to previously received
packets; checking a newer epoch cannot revoke plaintext or old keys already held.

Storage nodes see group/epoch, public member fingerprints, author, recipient
count, packet lengths, and traffic patterns. Item IDs, titles, revisions, and
values are inside the encrypted payload. There is no padding or metadata-hiding
transport in this milestone.

## Durable ciphertext spool

`CiphertextSpool` uses a separate owner-private directory and process-exclusive
file lock. `put` verifies public membership and signature before atomically
writing a private file, syncing the file and the parent directory on Unix.
An identical retry revalidates and syncs the existing object before returning
the same address. A corrupt existing object fails instead of being replaced.
Reads reverify signatures and ciphertext addresses against current membership.
Inventory is sorted and paginated; entries are possession candidates until read
and verified, not proof that their encrypted updates have been applied.

There are no reader keys in the spool. A can produce a packet for A, B, and C;
B can durably store it with public membership alone, restart while locked, and
forward the identical bytes to C after A goes offline. C can then decrypt using
its own reader key. This path is covered by an in-process test, not a running
network service or a mobile background-execution guarantee. Native filesystem
durability and lifecycle acceptance, especially Windows, still require testing.

Bounds: 16 readers, 4,096 revisions per update, 1 MiB encoded update, 2 MiB
packet, 4,096 stored objects (including orphan temporary files), and at most 128
inventory entries per page. Personal-item validation retains its own smaller
content bound. The caller supplies a nonzero disk-byte quota. Orphan temporary
files count against quota but never appear as delivered packets. Full stores
fail without eviction; there is no cleanup/compaction or acknowledgement policy
yet. Retrying byte-identical packets is idempotent; independently re-encrypting
the same revision creates a new ciphertext object.

## Remaining integration

Persist reader seeds under the local vault's protection; authenticate membership
and epoch changes; publish pending journal heads and recover publication after
crashes; apply incoming revisions transactionally with replay/conflict handling;
distinguish ciphertext receipts from applied acknowledgements; then connect the
spool to the background process, iroh, QR pairing, and device status UI. None of
those behaviors should be inferred from `VerifiedPacket` or a successful `put`.

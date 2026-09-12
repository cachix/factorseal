# macOS cryptography, identity migration, and isolation

This work covers Secure Enclave ML-DSA signing, a common signing-provider
interface, identity migration design, parser/network process isolation, macOS
Enhanced Security, and an ML-KEM wrapping prototype. Native acceptance is a
separate verification requirement; Linux tests do not establish Secure Enclave
behavior or macOS runtime compatibility.

## Signing contract

Vault commits and permission challenges use `SigningProvider`. Both providers
produce pure ML-DSA-65 signatures with an empty context over the existing
domain-separated transcript. CryptoKit output is independently verified with
RustCrypto before the operation can commit. A native failure is an error,
never permission to generate a replacement key or choose a software signer.

New native macOS vaults use CryptoKit Secure Enclave keys when the macOS 26 APIs
are available. Other platforms and older macOS retain the Rust provider.
The hardware key is created with `privateKeyUsage` and
`WhenUnlockedThisDeviceOnly`. The vault's configured AND/OR unlock policies
protect its opaque reference: that reference is AES-256-GCM encrypted under
the installation root, with an AAD domain binding the provider, installation,
and vault IDs. It is unwrapped only for a signing operation. This avoids a
biometric prompt on every database commit while keeping the reference behind
the vault's unlock ceremony.

An enclave reference is a capability, not public data. Someone who obtains it
on its original device may be able to request signatures while the key's ACL
allows access. Hardware isolation prevents exporting the private key; it does
not prevent misuse by a compromised authorized worker. The unsealed vault root
and plaintext secrets still exist in worker memory.

Metadata version 9 accepts exactly one of `signing_seed` or `enclave_mldsa65`.
The former preserves the version 7/8 serialized shape. The latter is a bounded,
root-encrypted opaque reference. Versions 7/8 cannot declare enclave signing;
enclave signing metadata must declare macOS. Unknown providers, mixed
providers, missing keys, malformed lengths, native errors, and mismatched
public identities all fail closed. `factorseal status` reports the persisted
`signing_backend` independently of the unlock backend.

## Identity migration and rotation decision

An upgrade must not silently rotate an existing identity. Existing version 7/8
vaults reopen with the software key that signed their history. Their public
key, `DeviceKeyId`, actor ID, authenticated grants, and database commit chain
remain unchanged. Availability of newer APIs does not change this behavior.

The first supported route to an enclave identity uses a separately initialized
vault and the existing encrypted archive export/import operations:

1. Export the old unlocked vault to a passphrase-encrypted native archive.
2. Initialize a new vault in a distinct directory on macOS 26+; verify that
   its reported signing backend is `secure-enclave-mldsa65`.
3. Import the archive and verify the restored inventory and values. This
   copies portable contents, not the old installation's device identity or a
   byte-for-byte continuation of its local database history.
4. Reauthorize applications for the new installation. Personal-sync membership
   is a separate reader identity and must be established explicitly; copying
   content must not enroll a new device automatically.
5. Keep the old installation available until verification and cutover finish.
   Its destruction is an explicit user operation, not part of an upgrade.

This route also covers lost hardware: restore contents onto a new installation
with new hardware keys. Neither enclave signing references nor ML-KEM
references constitute a backup transferable to another Mac.

In-place rotation is deferred. It cannot be implemented by replacing
`public_signing_key` in factorseal.json: old commits, permission proofs, and
actor identifiers refer to the old key. A future design needs an authenticated
old-to-new key transition, verification across epochs, transactional recovery
spanning metadata and the database, and an explicit caller-grant policy. It
must retain old public keys for historical verification and must not pretend
that importing the old software seed makes that seed non-exportable.

## Process isolation requirements

Desktop now supervises a separate `factorseal-network` process,
outside both the vault worker and Desktop's secret-bearing UI.
The networking helper possesses only its transport identity,
ciphertext spool, public membership state, and narrowly scoped inherited IPC.
It must not gain Keychain access, vault database access, a general vault grant,
or authority to approve its own pairing requests.

Raw client request parsing happens in `factorseal-parser` before typed
requests reach the vault service. The service remains responsible for peer
identity, request IDs, size limits, authorization, signature checks, and all
semantic validation. A helper's output is untrusted. A helper crash, malformed
reply, or timeout must fail the request, never trigger parsing in the worker.
Helpers must start without inheriting vault keys or arbitrary descriptors.

Both executables are installed beside the CLI. Each starts with private
inherited IPC and no parent environment variables. Windows receives
`SystemRoot` and `LOCALAPPDATA`, obtained directly from OS APIs for native
runtime and AppContainer initialization.
Unix descriptors other than stdin/out/err
are closed before untrusted input is processed; Windows inherits only the
explicit private pipe handle. Linux uses seccomp for the
parser and Landlock ABI 3 plus seccomp for networking. This requires kernel
support for `close_range` and fully enforced Landlock ABI 3 (Linux 6.2+);
missing enforcement is a startup error. The network process can access its
spool and public runtime/CA files, create threads, and use IP networking. It
cannot open existing Unix sockets, inspect other processes, execute programs,
or use kernel keyrings. Its private socket pairs grant no access to local
services. macOS uses a default-deny Seatbelt policy. Native probes verify
allowed spool, thread, and UDP operations and denied outside files, existing
Unix sockets, shell execution, and parent signals. Native macOS also passes
network startup, restart with the same identity, and concurrent-view tests.

The private CBOR protocol has finite frame deadlines, size and nesting bounds,
definite-length items, and locked scratch buffers for decoding. The parent
revalidates parsed vault requests. Pairing changes require a matching one-use
permit derived from the current Desktop action; background transport work
cannot approve its own pairing requests. Pairing state and device identities
shown by Desktop come from replies received directly from the vault host;
the network helper cannot substitute its own labels or pairing state in a
view reply. Transport failures terminate and reap
the child. A valid operation rejection does not terminate a healthy helper.

Windows uses creation-time less-privileged AppContainers without writable
profiles. Each launch registers its own random identity and unregisters it
after the child exits; only public identity metadata may remain if the parent
crashes. The launcher grants that identity access to the spool again when
restarting, preserving the transport key. The parser receives no capabilities;
networking receives IP and
platform certificate-validation capabilities and access to its private spool.
Helpers execute private read-only copies of the installed binaries. An
atomically attached job disallows child processes and terminates helpers when
the owner exits. The implementation passes Windows cross-compilation and lint
checks. Native Windows verifies the LPAC security attribute, exact capability
set, parser request processing, and the network probe's allowed private-file,
thread, and UDP operations alongside denied vault access and process creation.
Native startup, restart, and concurrent-view checks also pass. Windows route
discovery uses netdev instead of WMI, and HRESULT-only error handling avoids
loading COM inside a helper. Netwatch is pinned to the Git commit submitted in
[upstream PR #226](https://github.com/n0-computer/net-tools/pull/226) until a
compatible release is available. Native tests verify that multi-megabyte buffers
remain locked after neighboring allocations are freed, and that both helper
roles can allocate protected protocol buffers under their restricted tokens.
The allocator expands the process working-set capacity only on lock-quota
exhaustion; OS locking remains mandatory. Two-account tests also pass for
private files, server-side pipe denial, and client-side authentication before
any request bytes are sent. Windows also passes the large-message duplex IPC
regression and three-device sealed courier acceptance. Nonblocking pipe writes
are capped below the native pipe buffer quota so large frames make progress
within the existing deadline.
Linux process tests cover basic permissions, parser requests, network
startup/restart, and concurrency. The opt-in three-device acceptance test has
also passed on Linux through the installed helpers and production discovery:
a sealed middle device forwarded ciphertext after the sender exited.
The equivalent native macOS acceptance also passes, including the private-IPC
backpressure regression. View writes run on a bounded worker queue so the
child's IPC reader can keep accepting vault callbacks while output is blocked.
Native CI runs the three-device acceptance on macOS and Windows after basic
helper checks succeed.

## Enhanced Security

The signing script applies common runtime entitlements to application/helper
executables, in addition to Hardened Runtime. These select Enhanced Security
version 1, additional platform restrictions, read-only dynamic-loader state,
and hardened heap restrictions. Libraries are not given process entitlements.
Provisioned application entitlements are merged with the common runtime
policy; local ad-hoc packages get runtime policy without Team-only Keychain
entitlements.

This does not claim Swift compiler protections for Rust code. Hardware memory
tagging, arm64e pointer-authentication compilation, and type-aware compiler
allocation support are not enabled by copying these runtime entitlements.
Native macOS CI passes signature, deployment-target, and load-command
inspection, CLI startup, and tests against the signed packaged parser and
network helpers. Provisioned application acceptance must still exercise GPUI,
Keychain, and database operations under the runtime restrictions.

## ML-KEM wrapping prototype and adoption decision

`hardwareseal::apple_pq::wrapping::MlKem768WrappingKey` is opt-in. The default
Apple protector remains the device-only Data Protection Keychain.

The prototype uses Secure Enclave ML-KEM-768, HKDF-SHA-256, and AES-256-GCM.
Each seal creates a fresh encapsulation and nonce. HKDF binds the complete
envelope header; AEAD authenticates the same header, including the label hash,
access policy, key reference, and encapsulation. The format rejects payloads
over hardwareseal's 64-byte limit, malformed reference lengths, unknown
versions, truncation, mismatched labels/policies, and authentication failures.
The enclave enforces the key's actual biometric policy during decapsulation.
Shared secrets and derived wrapping keys are temporary zeroizing buffers;
they are not claimed to stay inside the enclave.

Do not replace Keychain wrapping yet. The Keychain path is not established to
be quantum-vulnerable; adding a public-key envelope is not automatically an
improvement. Adoption requires physical-device biometric and restart tests,
latency/size measurements, review of the key-reference lifecycle and rollback
properties, and an explicit crash-safe migration of each unlock slot. The
prototype cannot revoke a retained envelope by deleting a local reference.

## Verification

The full helper acceptance test pairs three synthetic vaults using production
discovery and relays. It stops the receiver, creates an item, verifies that a
sealed middle device stores the sender's exact ciphertext, then terminates the
sender and restarts the receiver. Success requires delivery and decryption
while the middle vault stays sealed. It is opt-in because it needs live
network services; it does not add test transport commands or sandbox bypasses
to the installed helpers:

```sh
cargo build --all-features --bin factorseal-network
cargo test --lib --all-features helpers_pair_and_deliver_through_a_sealed_courier_after_sender_exit -- --ignored --nocapture
```

Portable tests cover existing vault state and migration, identity-bound
software signing, provider ambiguity, unsupported-platform rejection, native
output bounds, and mutation of every ML-KEM envelope byte. Native tests are
explicitly ignored until invoked on physical macOS 26+ hardware:

```sh
cargo test --lib --all-features secure_enclave_signatures_verify_with_rustcrypto_after_reopening -- --ignored
cargo test -p hardwareseal --features apple hardware_envelopes_reopen_without_a_live_key_object -- --ignored
cargo test -p hardwareseal --features apple compare_mlkem_and_keychain_wrapping_costs -- --ignored --nocapture
```

These tests do not replace biometric enrollment/cancellation/reboot acceptance
or signed app packaging validation. A missing Mac/SDK is missing evidence,
not a passed check.

The comparison requires a provisioned test executable with Data Protection
Keychain access. It seals and verifies twenty synthetic 32-byte roots per
backend, reports key generation, first-operation and latency percentiles, and
reports the returned envelope size. Keychain's returned reference size excludes
its separate platform storage. Measurements use possession-only authorization;
they do not measure biometric prompts or establish revocation/recovery parity.
Each run uses a random scratch Keychain label and removes only that label.

## Sources

- [Secretive's Secure Enclave implementation](https://github.com/maxgoedjen/secretive/blob/2382cd01536c37a3064ff1187adb656caa40aadb/Sources/Packages/Sources/SecureEnclaveSecretKit/SecureEnclaveStore.swift)
- [Apple CryptoKit quantum-secure workflows](https://developer.apple.com/documentation/cryptokit/enhancing-your-app-s-privacy-and-security-with-quantum-secure-workflows)
- [Apple Enhanced Security](https://developer.apple.com/documentation/xcode/enabling-enhanced-security-for-your-app)

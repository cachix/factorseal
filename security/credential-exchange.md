# Credential exchange

FactorSeal uses [CXF 1.0 with the March 2026 errata](https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html)
for personal credential interchange. It uses [age v1](https://age-encryption.org/v1)
for passphrase-encrypted or hybrid post-quantum recipient-encrypted files. Neither the encryption envelope nor the primary
credential schema requires FactorSeal to decode it.

## Boundaries

`transfer::cxf::export_json` and `import_json` operate on plaintext in memory.
The CLI and desktop `cxf-age` option encrypts/decrypts that payload. Plain CXF
JSON is not exposed as a file-export option. This is not CXP, a trusted OS
recipient picker, or a guarantee that any particular password manager supports
importing the file. Possession of the file and passphrase or matching private
identity permits decryption. Recipient encryption does not authenticate the
sender: anyone with the public recipient can create an export for it.

## Hybrid recipient encryption

`--recipient-file` selects the standard `age1pq1…` public recipient on export;
`--identity-file` selects its `AGE-SECRET-KEY-PQ-1…` identity on import. Desktop
offers the same choice as **Post-quantum key**. Neither mode silently falls back
to the other. Only one hybrid key per file is accepted, with comments and blank
lines allowed. Key files are limited to 64 KiB, and identity files must satisfy
the same private regular-file checks as passphrase files. Encrypted identities,
plugin identities, classical recipients, and multiple-key files are unsupported.

The pinned Rust age library has no native hybrid identity/recipient yet. Our
adapter implements only the specified Bech32 key and `mlkem768x25519` stanza
encoding. The existing `hpke` crate supplies X-Wing (ML-KEM-768 + X25519),
HPKE Base mode, HKDF-SHA256, and ChaCha20-Poly1305. It uses the specified info
`age-encryption.org/mlkem768x25519` and empty AAD. The age library still handles
random file keys, header authentication, and payload streaming. Export labels
prevent mixing hybrid recipients with classical recipients. No external
process or age executable is needed during normal import/export.

The adapter checks the encapsulation's canonical base64 encoding and exact
1120-byte length and the wrapped file key's 32-byte ciphertext length before
attempting HPKE decryption. Private key buffers use zeroizing storage; the
HPKE dependency enables RustCrypto X-Wing's zeroization support.

Both modes use age v1's **128-bit random file key**. Adding hybrid recipients
does not increase the file-key security margin or make the whole format a
256-bit design. See [age's post-quantum security analysis](https://words.filippo.io/post-quantum-age/).
Password mode has no asymmetric exchange, and passphrase entropy still limits
its strength. The native AES-256-GCM archive is unchanged.

The native `.factorseal` archive remains the complete portable backup format.
It includes project partitions, addresses, system-keyring records, and expiry
deadlines that CXF does not natively describe. It retains its version and
existing readers. Forcing those records into a private CXF extension would not
give other applications useful interoperability and would add a second copy of
the same backup schema.

## Mapping and preservation

The encoder writes a versioned CXF header, one personal account, and stable
hashed item identifiers. Standard `basic-auth`, `api-key`, `credit-card`,
`person-name`, `totp`, and `note`
credentials are used where mapped. Other supported fields are represented as
typed `custom-fields` credentials. Website scopes include the saved URLs.

`org.factorseal.item` and `org.factorseal.field` are vendor extensions for local
IDs, categories, section/field order, concealment, folder/archive flags, and
types without a direct CXF equivalent. Values remain in standard CXF fields;
the extensions do not contain another serialized personal item. TOTP URI
spelling is normalized while retaining issuer, username, algorithm, period,
digits, and secret. Consumers may ignore vendor extensions; this export is not
advertised as a lossless replacement for a native archive.

Unknown credentials and properties are retained as encrypted source metadata
and surfaced in the import summary. They are not counted as authentication
support. Re-export preserves CXF account identities, collections, unknown
extensions, and unsupported credentials while applying current field values.
Deleted mapped values are removed from the outgoing source structure. Editing
an opaque credential as a raw field, conflicting source-account metadata, and
source data from other formats still block CXF export. Newly created structured
or numeric fields also require a native archive. A CXF
file credential refers to out-of-band bytes: without an attachment transport,
the importer rejects it rather than recording a successful file import.

The importer authenticates and prepares the complete input before beginning
vault writes, including encoding each item against the vault's size limit.
Existing entries are kept unless replacement is explicitly selected. As with
other manager imports, subsequent storage/IPC failures are not a transaction
across all imported records. Desktop imports show a preview after preparation
and before writing; the CLI's `import --dry-run` validates and shows counts
without connecting to a vault. Interrupted commits report confirmed progress
and note that a lost reply may conceal a successful last write. Retrying the
same input with replacement disabled retains already imported identities.
Keep the old vault as a fallback.

Version 2 of the FactorSeal item extension retains the original account and
item identifiers on foreign CXF records. The local identity must match their
deterministic projection. Field and TOTP metadata follow current labels,
section order, folders, and archive flags; opaque credentials keep their source
structure. Empty accounts with metadata are rejected because the current vault
has no standalone account record in which to retain them.

The [Apple adapter](../platform/apple/README.md) contains a macOS 26 in-memory
transport and SDK compatibility tests. It is not integrated into the desktop
application or signed package. Apple Passwords acceptance and provider-extension
signing remain prerequisites for enabling system transfer.

## Resource and memory limits

- CXF plaintext is limited to 128 MiB and 100,000 items. Each encoded personal
  record must fit the existing 512 KiB limit.
- Encrypted input is limited to 256 MiB. Decrypted output is bounded and must
  authenticate completely before being passed to the parser.
- Production age exports use scrypt with log N = 17 (128 MiB at r = 8).
  Imports cap log N at 18 (256 MiB). Excessive work factors fail without
  performing that work. Unit tests lower the export cost using `cfg(test)`.
- JSON trees and plaintext output buffers use the existing zeroizing wrappers.
  Passphrases use age's secret-string type. This does not claim that every
  allocation inside third-party parsers and cryptographic libraries is locked
  or zeroized.

The application applies its existing new-passphrase strength policy. Output
uses the existing private, atomic file writer. File transfer does not provide
the phishing resistance of an OS-controlled recipient selection ceremony.

## Validation

Tests decode exported synthetic records using the independent
`credential-exchange-format` crate, then import its serialized output. That
crate is test-only because its types do not zeroize secrets. Tests also cover
editing third-party login data, TOTP parameters, unknown metadata, invalid
identifiers/versions, missing files, record size limits, wrong passphrases,
truncation, and ciphertext tampering. These establish format compatibility;
they do not establish compatibility with every vendor's product UI.

An age 1.3.1 Go CLI fixture independently verifies decryption. During initial
implementation, the same Go CLI also decrypted a production-cost FactorSeal
export and its plaintext matched byte for byte. The dependency revisions are
pinned to upstream fixes for RustCrypto version compatibility and the removal
of the unmaintained `proc-macro-error2` helper, with matching Nix source hashes.

An additional Go age 1.3.1 hybrid fixture tests the standard hybrid identity
and recipient encodings. Tests cover wrong keys, multi-chunk authentication,
malformed stanzas, non-canonical base64, classical/mixed recipient rejection,
key-file permissions and limits. The opt-in `hybrid_go_cli_interoperability`
test checks Go age decrypting a freshly generated FactorSeal export:

```sh
FACTORSEAL_TEST_AGE_BIN=/path/to/age cargo test --no-default-features --features transfer --lib hybrid_go_cli_interoperability -- --ignored
```

The transfer fuzz entry point includes the CXF JSON parser and both hybrid key
parsers. Password stretching is deliberately excluded from fuzz iterations.

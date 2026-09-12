# Using FactorSeal

[Back to the project overview](../README.md).

## Desktop unlock support

| Platform | Biometric method | Intended hardware binding | Status |
| --- | --- | --- | --- |
| macOS | Touch ID | Keychain/Secure Enclave key-use policy | Implemented; physical-device release acceptance remains |
| Windows | Windows Hello fingerprint, face, or PIN | TPM sealed-data object nested inside Windows Hello PRF encryption | Implemented; physical-device prompt and policy acceptance remains |
| Linux | No portable built-in biometric path | TPM 2.0 supports hardware wrapping, but `fprintd` does not provide a hardware-bound secret | Password-backed TPM unlock only |

The vault encryption and ML-DSA signatures are designed to resist quantum
attacks. Native biometric enforcement still inherits the cryptographic and
certification properties of Secure Enclave or Windows Hello, so Factorseal does
not claim that those complete platform paths are post-quantum certified.

## Quick start

Factorseal requires a supported platform enclave: TPM 2.0 on Linux and Windows,
or Secure Enclave on macOS. Software keyring and DPAPI-only fallbacks are
rejected. Once the `factorseal` binary is installed, create a vault:

```console
$ factorseal init
```

When run in a terminal, initialization briefly introduces the vault and asks
you to choose password, biometric, password AND biometric, or password OR
biometric unlocking. The default is password. It then creates the
hardware-protected vault, authorizes that exact CLI executable for the durable
keyring, and leaves the vault sealed. Non-interactive initialization also
defaults to password unless `--unlock` is passed explicitly.

Password slots use memory-hard Argon2id by default. Deployments that require a
NIST-standardized algorithm profile can opt into PBKDF2-HMAC-SHA-256 with
`factorseal init --fips`. This selects algorithms suitable for a future
validated provider boundary; it does not make the current build FIPS validated.

Unlock policies use AND inside one comma-separated group and OR between
repeated groups. Platform hardware binding is implicit in every group:

```console
$ factorseal init --unlock password,biometric
$ factorseal init --unlock password --unlock biometric
$ factorseal init --fips
```

The first policy requires password AND biometric approval. The second accepts
password OR biometric approval. A biometric-only policy does not ask for a
Factorseal password. The first repeated group is the preferred unlock method;
override it when starting the agent, for example `factorseal agent --unlock
biometric`.

Start an unsealed service in one terminal:

```console
$ factorseal agent
```

Or use the separately packaged graphical host:

```console
$ factorseal desktop
```

Desktop initializes and unseals the same vault through a dedicated CLI worker,
which hosts the authenticated endpoint. On Linux, Desktop hosts the
`org.freedesktop.secrets` adapter and accesses the worker through authenticated
IPC. The GUI releases its unlock password after
handoff; the worker wipes that factor before serving. Install the CLI alongside
Desktop or set `FACTORSEAL_CLI_EXECUTABLE` to its absolute path. It is an
alternative to `factorseal agent`, not a client of it, so do not configure both
to autostart. Repeated Desktop launches activate the existing per-vault
instance. On Linux, the Desktop package registers D-Bus activation for
`org.freedesktop.secrets`. Desktop keeps answering while sealed, but credential
searches open a compact access dialog and resume after approval and authentication. Native
socket and SecretSpec clients also require Desktop to be unsealed first.
Request parsing and personal sync run in separate confined helper processes
installed beside the CLI. On Linux the sync helper requires Landlock ABI 3, so
personal sync needs kernel 6.2 or later; distributions such as Debian 12 and
Ubuntu 22.04 ship older kernels and cannot run it. The parser helper works on
every supported kernel.
Sealing removes the native service endpoint and all unwrapped vault keys.

If the vault does not exist yet, `factorseal agent` stays alive, logs the
initialization instruction, and continues automatically after `factorseal init`
creates it. Packaged background launchers use this same behavior on every
desktop platform.

Then store a durable project secret from another terminal:

```console
$ factorseal set --project my-app github --field token
$ factorseal get --project my-app github --field token
$ factorseal delete --project my-app github --field token
```

Browse project and address metadata without retrieving any values:

```console
$ factorseal projects
"my-app"
$ factorseal list --project my-app
{"kind":"native","coordinates":{"item":"github","field":"token"}}
```

Show what changed in a project, newest first, without reading any value:

```console
$ factorseal history --project my-app
{"version":1,"seq":1,"at":1756742400,"operation":{"type":"delete"},"address":{"domain":"secret_spec","address":{"kind":"native","coordinates":{"item":"github","field":"token"}}},"previous_version_id":"…","provenance":{"source":"caller","principal":{…}},"device_key_id":[…]}
```

An entry names the address, the operation, the value version it created or
replaced, and the transport-authenticated caller or service reason it was
performed for. It never contains the value itself.

All three commands follow every bounded vault cursor automatically. Pass
`--json` to emit one JSON array instead of JSON-quoted projects or one compact
object per line.

`set` prompts without echo when standard input is a terminal. It can also read
exact bytes from standard input or `--value-file`:

```console
$ printf '%s' 'secret value' | factorseal set --project my-app github --field token
$ factorseal set --project my-app github --field token --value-file ./token.bin
```

`--project` may also come from `SECRETSPEC_PROJECT`. Without `--field`, the CLI
stores a conventional SecretSpec address using `--profile` (which defaults to
`default`). With `--field`, it stores a native SecretSpec address. `get` writes
the exact stored bytes without adding a newline. `factorseal status` reads
validated public metadata without unsealing and reports whether a matching
service is reachable.

Replacing or upgrading the binary changes its executable digest. Stop the
service and run `factorseal grant-cli` to authorize the new CLI executable. The
project approval must also be renewed for the new executable.

Seal the running service immediately when it is no longer needed:

```console
$ factorseal seal
```

### Import and export

Create or restore a portable, versioned FactorSeal archive while the vault is
unsealed:

```console
$ factorseal export backup.factorseal
Archive passphrase:
Confirm archive passphrase:
$ factorseal import backup.factorseal
Archive passphrase:
$ factorseal import backup.factorseal --replace-existing
```

Native archives include every portable vault document and are encrypted with
AES-256-GCM using a separate Argon2id-stretched passphrase. For unattended
jobs, use `--passphrase-file` with a private regular file (mode `0600` on
Unix). Imports preserve existing entries unless `--replace-existing` is
explicitly passed. Exports read the live vault and fail if its contents change
during collection; retry the export in that case. Linux keyring metadata and
values restore together, preserving unrelated destination items. Archive v2
readers also convert v1 archives during import.

Password-manager formats operate on Personal Secrets only:

```console
$ factorseal import bitwarden.json --format bitwarden-json
$ factorseal export onepassword.csv --format 1password-csv
$ factorseal export keepass.csv --format keepass-csv
```

Bitwarden JSON, 1Password CSV, and KeePass CSV are plaintext formats. FactorSeal
prints a warning and writes exports through a private temporary file before
atomically replacing the destination. Exports reject items whose fields or
metadata the selected format cannot preserve; use an encrypted FactorSeal
archive for a lossless backup. Duplicate imported titles receive stable,
collision-free suffixes.

### Personal item types and migration

Personal items use a versioned record with a stable ID, category, ordered sections,
and typed fields. Templates cover logins, secure notes, cards, identities, SSH
keys, API credentials, passports, bank accounts, documents, and generic secrets.
Fields have independent IDs and labels, so repeated labels and multiple passwords
are supported. The desktop creation form offers templates and custom fields;
values use masked, locked-memory input, including multiline values.

Existing v1 records and UTF-8 secret values migrate on read; subsequent writes use
v2. Native encrypted archives retain all sections, fields, and source metadata.
Unknown CSV columns become concealed custom fields. Bitwarden custom-field types
and linked-field IDs are preserved. Unmapped Bitwarden properties are retained in
encrypted source metadata and prevent exports to formats that would discard them.

Import 1Password's richer export with:

```console
$ factorseal import account.1pux --format 1password-1pux
```

1PUX v3 imports preserve sections, typed values, source metadata (including password
history), and files. Files are currently stored as separate document items; source
metadata retains their document IDs. The importer never extracts ZIP paths to disk,
limits expanded archives to 128 MiB, and rejects missing referenced files. Each
encoded personal item is limited to 512 KiB to fit the vault protocol. An oversized
item fails preparation before any imported items are written. 1PUX is import-only;
use an encrypted FactorSeal archive to back up these richer records. Preserving
passkey or other unrecognized source data does not make it usable for authentication.

### Personal sync (experimental)

Desktop can pair devices using QR codes or tickets with explicit code approval
and exchange encrypted personal-item changes through an iroh courier. Once
configured, the courier can continue transferring ciphertext while Desktop
remains open and the vault is sealed. Applying changes requires the vault worker
to be unsealed. Project secrets, application grants, and device keys remain local.

Sync is experimental. Mobile camera integration, peer application receipts, a
conflict-resolution chooser, and controller transfer and removal UI are still
missing. A connected peer does not confirm that it has applied your changes.
Personal history includes old and deleted values, and newly enrolled readers
receive that history. Sync does not replace a portable backup.

See the [personal sync boundary](../security/personal-sync-wire.md) for protocol,
history-retention, and platform limitations.

## Diagnostics

FactorSeal keeps local crash reports and bounded operation logs for Desktop,
the CLI, and vault workers. Export them from Desktop's Settings → Diagnostics,
or run `factorseal diagnostics --output factorseal-diagnostics.json` without
unlocking the vault. Desktop can automatically submit crash reports when a Sentry
DSN is configured; its Diagnostics settings control submission. See the
[diagnostics guide](../factorseal-desktop/README.md#crash-reports-and-logs) for
storage, privacy, retention, and crash-capture limits.

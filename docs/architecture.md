# Architecture

FactorSeal is a local credential store. It does not model people or machines as
encryption recipients.

```text
application
    |
keyring-core: service + account
    |
unlocked FactorSeal session
    |               \
encrypted entry      zeroizing vault key
```

## Vault formats

Version 2 is the current format. Initialization creates a random 256-bit vault
key and a vault-specific platform key through `hardware-enclave`. The platform
key encrypts either the complete vault key or one share of it.

Version 1 derives a wrapping key from a password with Argon2id. It remains
readable only when the non-default `password` feature is enabled. Migrating
from version 1 to version 2 replaces `vault.json` after a successful hardware
wrap; credential entries remain unchanged.

Hardware key labels include the random vault ID. Platform metadata and Linux
TPM blobs live under the vault's `hardware/` directory. A copied TPM blob is
useless without the TPM that created it.

## Two-factor composition

A `hardware+yubikey` vault uses a 2-of-2 XOR construction:

```text
vault key = platform share XOR YubiKey share
```

Both shares are uniformly random when considered independently. Platform
hardware encrypts the platform share. For the other share, FactorSeal asks a
PIN-protected RSA-2048 key in YubiKey PIV slot `9d` to sign a domain-separated,
vault-specific challenge. The `yubikey` crate performs SHA-256 and
EMSA-PKCS1-v1_5 encoding. FactorSeal hashes the deterministic signature into an
XChaCha20-Poly1305 wrapping key.

The signature is not stored. Vault metadata records the device serial, PIV
slot, algorithm, nonce, and encrypted share. Unlock therefore requires the
same platform hardware, the selected YubiKey, and its PIN. A PIV touch policy
can additionally require physical presence.

## Credential storage

Each `(service, account)` pair maps to one file beneath `entries/`. The filename
is a SHA-256 digest, so user-controlled names cannot escape the vault.

XChaCha20-Poly1305 encrypts every value with a fresh 192-bit nonce. The vault
ID, service, and account are authenticated as associated data. Moving an entry
to a different name or vault therefore fails authentication.

On Unix, FactorSeal creates vault directories with mode `0700`, creates the
initial configuration with mode `0600`, and refuses to open a vault directory
that is accessible to group or other users.

## Session model

With the `keyring` feature, the keyring adapter owns an unlocked vault. It
holds one vault key but no decrypted credential cache. Every `get` performs a
fresh authenticated decryption and returns only the requested value.

The CLI currently starts a new session for each invocation. A desktop unlock
agent is planned to provide an “authorize once” experience across processes.
That agent must have a bounded lifetime, support explicit locking, and retain
only the vault key.

## Security boundary

Hardware binding protects a copied vault from offline decryption. It cannot
prevent an already-authorized application from reading and exfiltrating a
credential returned to it. The desktop agent therefore also needs application
authorization and session-expiry controls; hardware binding alone does not
solve an active compromised-session threat.

Credential encryption has a post-quantum symmetric security margin, but the
hardware wrapping mechanisms are currently P-256 and RSA-2048. FactorSeal
cannot offer end-to-end post-quantum hardware binding until the relevant
hardware APIs expose suitable primitives.

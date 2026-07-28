# Security

FactorSeal is an early prototype and has not received an independent security
audit. Do not use it to protect production secrets yet.

Please report suspected vulnerabilities privately to the maintainers. Do not
open a public issue until a fix is available.

## Design requirement

Two-factor authentication (2FA) is required by design for every supported
persistent vault. The current compliant configuration reconstructs the vault
key from independently protected platform-hardware and YubiKey shares, both of
which are required.

Hardware-only version 2 vaults and legacy password vaults remain accessible as
prototype compatibility paths. They do not meet this design requirement and
must not be treated as supported deployment profiles.

## Current guarantees

- The vault key is random and 256 bits.
- Version 2 requires a Secure Enclave or TPM backend and rejects Linux keyring
  and Windows DPAPI fallback.
- The selected platform backend is recorded and must match at unlock.
- A configured biometric access policy is recorded and must be enforced again
  when the platform key is opened; unsupported platforms fail closed.
- YubiKey two-factor vaults split the key into independently protected random
  shares; both shares are required.
- Vault-key and credential encryption use XChaCha20-Poly1305.
- Credential identities and vault IDs are authenticated.
- Plaintext return values and in-process vault keys and factor shares use zeroizing
  buffers where the public APIs permit.
- The keyring adapter does not cache decrypted credentials.
- Unix vault directories are required to exclude group and other users.
- Legacy password wrapping is compiled only with the non-default `password`
  feature and uses Argon2id with 64 MiB of memory and three iterations.

## Current limitations

- The CLI and public API still permit creating and unlocking hardware-only
  version 2 vaults, with or without a biometric gate. Biometrics authorize use
  of the platform key but do not create an independent second key share.
  Removing those transitional paths is required before the implementation
  enforces the 2FA design invariant universally.
- Hardware integrations have not been exercised in this repository's automated
  tests on every supported platform or TPM model.
- `hardware-enclave` 0.2.10 reports native Linux encryption handles as
  `Keyring` even after selecting its TPM implementation. FactorSeal requires
  the native TPM blob pair before accepting that case. Remove this workaround
  when the dependency reports the selected encryption backend directly.
- The YubiKey provider supports one pre-provisioned RSA-2048 PIV key in slot
  `9d` on firmware 5.2.3+. It does not provision keys, support backup
  YubiKeys, or provide recovery.
- Passkey and authenticator-app providers are not implemented. A passkey
  provider must use stable PRF/`hmac-secret` output, and a phone provider must
  hold independent key material. TOTP-only verification is not accepted as an
  offline share-protection mechanism.
- Losing or resetting the platform hardware or required YubiKey permanently
  loses access unless secrets were separately backed up. A recovery-key export
  is not implemented.
- P-256 hardware wrapping and RSA-2048 PIV are not post-quantum algorithms.
- The CLI unlocks separately for every command; there is no bounded desktop
  session agent yet.
- Windows filesystem ACL validation is not implemented.
- Memory locking, process-dump protection, rollback protection, rate limiting,
  application authorization, and audit logging are not implemented.
- `keyring-core` must return an ordinary `Vec<u8>` to clients, so the adapter
  cannot guarantee zeroization after returning a secret.
- An authorized or compromised client can exfiltrate any secret returned to
  it. Hardware binding primarily protects the vault at rest and off-machine.

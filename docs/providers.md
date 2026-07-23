# Unlock providers

An unlock provider releases or reconstructs the vault key after local
authorization. It is not an encryption recipient and never handles credential
plaintext.

## Platform hardware

Platform hardware is the default and is required for every version 2 vault.
FactorSeal uses `hardware-enclave` and accepts only these backends:

| Platform | Accepted backend |
| --- | --- |
| macOS | Secure Enclave |
| Windows | TPM 2.0 |
| Linux | Native TPM 2.0 |
| WSL | Windows TPM bridge |

Windows DPAPI and Linux keyring fallback are explicitly rejected. The selected
backend is recorded in `vault.json`, and later unlocks must match it.

Native Linux requires the `tpm2-tss` runtime and access to `/dev/tpmrm0`, or a
reachable `tpm2-abrmd` resource manager.

## YubiKey

The optional `yubikey` feature adds a required second factor. It uses the PIV
key-management slot (`9d`) and requires:

1. An existing RSA-2048 private key and matching certificate.
2. Firmware 5.2.3+ with PIV slot metadata support.
3. A PIN policy other than `Never`.
4. PC/SC support on the host.

FactorSeal does not generate or overwrite the PIV key. The slot's touch policy
controls whether the user must physically touch the device.

The YubiKey protects one random share while platform hardware protects the
other. This is an `all` policy; neither factor independently wraps the complete
vault key.

## Password

Password support is behind the non-default `password` feature. It exists for:

- reading and migrating version 1 vaults;
- explicit development and headless testing;
- changing a version 1 password before migration.

It is not added to version 2 as an `any` fallback. Such a fallback would allow
a copied vault and password to bypass its machine binding.

## Provider contract

Unlock providers must:

1. Bind their vault-key share to the expected device.
2. Perform configured authorization for a new unlock session.
3. Avoid persistent plaintext vault-key caches.
4. Return only a vault-key share, never stored credential values.
5. Zeroize transient private material where the platform permits.
6. Distinguish missing hardware, denied authorization, and backend failures.
7. Refuse a silent downgrade to a weaker provider.
8. Support explicit lock and bounded session expiry when the agent is added.

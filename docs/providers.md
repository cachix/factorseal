# Unlock providers

An unlock provider releases or reconstructs the vault key after local
authorization. It is not an encryption recipient and never handles credential
plaintext.

## Factor policy

Two-factor authentication (2FA) is required by design for every supported
persistent vault. The current policy is 2-of-2: platform hardware protects one
random share and a PIN-protected YubiKey protects the other. Neither factor
independently protects the complete vault key.

Biometrics are a user-verification gate on a platform key operation, not a
separate key-share provider. The prototype retains hardware-only, biometric-
gated hardware-only, and legacy-password compatibility paths for development
and migration. They do not satisfy the independent-share policy and are not
supported deployment profiles.

## Platform hardware

Platform hardware is the first required factor for every version 2 vault.
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

## Biometric

`init --biometric` configures the platform hardware key with the
`BiometricOnly` access policy exposed by `hardware-enclave`. The policy is
stored in `vault.json` and supplied again on every open; a platform that cannot
enforce it returns an error instead of downgrading to an interaction-free key.

The current dependency supports platform biometric enforcement on macOS and
Windows. Native Linux does not expose a corresponding hardware-enforced
biometric policy.

Biometric verification gates the platform share. It does not add an
independently protected share, so it is an additional check in a compliant
`hardware+biometric+yubikey` vault and not a replacement for the YubiKey in the
current 2-of-2 construction.

## YubiKey

The current required second-factor provider is enabled by the `yubikey` Cargo
feature. It uses the PIV key-management slot (`9d`) and requires:

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

## Passkeys

Passkeys are a target provider, not an implemented provider. A FactorSeal
passkey must return stable, credential-bound secret material through WebAuthn
PRF or CTAP `hmac-secret`, with user presence or verification enforced by the
authenticator. That output can derive a key that wraps one random vault share.

An ordinary passkey authentication signature is not sufficient. Signatures
are authentication evidence, may be randomized, and are not a stable secret
from which the same wrapping key can safely be reconstructed.

## Authenticator apps

A phone authenticator is also a target provider. To meet the provider
contract, the phone must retain independent key material and release or help
derive a share only after answering a vault-bound challenge.

Conventional TOTP is deliberately not treated as a share-protecting factor in
an offline vault. The local verifier would need the TOTP seed in order to
verify codes; anyone who recovered that verifier state could calculate the
same codes. TOTP could gate an online, rate-limited service, but that would be
a different trust and availability model.

## Provider contract

Unlock providers must:

1. Enforce an `all` policy with at least two independently protected factors.
2. Bind their vault-key share to the expected device.
3. Perform configured authorization for a new unlock session.
4. Avoid persistent plaintext vault-key caches.
5. Return only a vault-key share, never stored credential values.
6. Zeroize transient private material where the platform permits.
7. Distinguish missing hardware, denied authorization, and backend failures.
8. Refuse a silent downgrade to a weaker provider.
9. Support explicit lock and bounded session expiry when the agent is added.
10. Record whether the factor protects key material or only gates another
    factor, so the policy cannot count one protected share twice.

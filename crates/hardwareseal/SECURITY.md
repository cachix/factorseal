# Security model

## Scope

`hardwareseal` protects short secrets at rest by binding them to one device. It
defends against copying a sealed envelope to another device and against
store-now/decrypt-later attacks on an asymmetric wrapping scheme.

After a successful unseal, the caller receives the plaintext in process memory.
The crate cannot protect that plaintext from a compromised process, kernel, or
debugger. Callers should keep the returned `Zeroizing<Vec<u8>>` alive for as
little time as possible.

## Cryptography

- Linux and non-biometric Windows policies create TPM 2.0 sealed-data objects
  beneath an AES-256-CFB restricted storage primary. SHA-256 names TPM objects
  and binds their public parameters.
- Windows biometric policies first create a TPM sealed-data object, then wrap
  that object with AES-256-GCM under a platform WebAuthn credential's 256-bit
  PRF output. Unsealing requires both Windows Hello user verification and the
  original physical TPM.
- Android creates a non-exportable AES-256-GCM key in Android Keystore, rejects
  keys whose `KeyInfo` reports software-only storage, and authenticates the
  envelope metadata as associated data.
- Apple stores the short secret as a device-only Data Protection Keychain item.
  With the biometric policy, `biometryCurrentSet` gates every retrieval and
  invalidates the item when biometric enrollment changes.

`hardwareseal` does not use public-key encryption to wrap the secret. Apple's
backend creates and immediately discards an ephemeral Secure Enclave P-256 key
only as a capability probe. The Windows Hello credential and WebAuthn protocol
may internally use classical public-key cryptography, so the complete Windows
biometric path is not claimed to be post-quantum certified. Its stored secret
envelope is encrypted with a credential-bound symmetric PRF output.

## Fail-closed rules

- Unsupported backends and policies return an error.
- Linux requires `/dev/tpmrm0`; it does not fall back to an unmediated TPM
  device or a software simulator.
- Windows rejects the explicit TBS emulator interface for TPM sealing and
  requires a user-verifying platform authenticator with PRF support for the
  biometric policy. It uses standard WebAuthn PRF input transformation, fresh
  per-envelope inputs, an application-owned prompt window, a bounded timeout,
  and validates the assertion's RP-ID hash, user-presence bit, and
  user-verification bit.
- Android rejects software-only Keystore keys.
- Envelopes bind their backend version, access policy, and SHA-256 label hash.
- Biometric authentication is never simulated with a separate, unbound prompt.

Linux and Android currently reject the biometric policy where the native
operation cannot yet bind a cryptographic factor to each unseal.

## Compliance

AES-256 and SHA-256 are commonly permitted by regulated cryptographic profiles,
but algorithm choice is not a validation. FIPS status depends on the exact TPM,
operating-system cryptographic module, device configuration, build, and product
boundary. This crate must not be described as FIPS validated without an
applicable certificate and deployment-specific assessment.

# Changelog

All notable changes to FactorSeal will be documented in this file.

## Unreleased

- Establish two-factor authentication as a design requirement for every
  supported persistent vault; hardware-only and legacy-password paths are
  prototype compatibility gaps, not deployment profiles.
- Bind version 2 vaults to macOS Secure Enclave or Windows/Linux TPM hardware,
  refusing DPAPI and Linux keyring fallback.
- Add PIN-protected YubiKey PIV 2-of-2 unlock using independent vault-key
  shares.
- Make password vault support non-default and add migration from version 1
  password wrapping to version 2 hardware wrapping.
- Add encrypted credential storage, CLI, and optional `keyring-core` API in a
  single crate.

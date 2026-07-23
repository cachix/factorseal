# Changelog

All notable changes to FactorSeal will be documented in this file.

## Unreleased

- Bind version 2 vaults to macOS Secure Enclave or Windows/Linux TPM hardware,
  refusing DPAPI and Linux keyring fallback.
- Add optional PIN-protected YubiKey PIV two-factor unlock using independent
  vault-key shares.
- Make password vault support non-default and add migration from version 1
  password wrapping to version 2 hardware wrapping.
- Add encrypted credential storage, CLI, and optional `keyring-core` API in a
  single crate.

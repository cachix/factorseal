# Changelog

All notable changes to FactorSeal will be documented in this file.

## Unreleased

- Replace the legacy file format with the per-user Factorseal vault and make
  `factorseal` the sole product CLI.
- Add the per-user vault: embedded Turso persistence, Automerge
  documents, encrypted and ML-DSA-65-signed change envelopes, scoped grants,
  bounded leases, and expiration.
- Add authenticated Linux, macOS, and Windows local transports plus native
  developer packaging inputs, an unsigned macOS pkg builder, and CI package
  smoke tests.
- Obtain the vault's nested factor from `--password-file`, an `--askpass`
  helper, or the controlling terminal, and ship askpass helpers with the macOS
  and Windows packages so both can keep unsealing the vault at login without a
  console and without writing the factor to disk. The helpers are interim:
  prompting and asking are planned to move into the vault itself.
- Seal and zeroize the vault from native Linux logind, macOS AppKit, and
  Windows power/session lifecycle notifications; bound IPC frame time as well
  as size so a stalled client cannot hold the vault indefinitely.
- Tag every envelope with its signature algorithm and bind that identifier
  into both the signed payload and the AEAD additional data, so a post-quantum
  or hybrid signature becomes a new `SignatureAlgorithm` variant rather than a
  format migration. Unknown or absent algorithms are refused rather than
  ignored. Envelope format version 2.
- Make the unreleased vault format post-quantum: version 2 uses ML-DSA-65 for
  vault identity, envelope signatures, and protected commit signatures.
- Verify signed Turso commit metadata against SQL rows and detect missing
  history, rolled-back heads, a single document rewound behind its newest
  commit, orphaned changes, scope tamper, and signature tamper when opening
  the store.
- Re-sign and compact the protected commit chain once it passes a bound,
  down to one commit and one snapshot per document. Every mutation appends a
  whole encrypted document snapshot, so an unpruned chain grew both the
  database and unseal latency without bound in the number of writes. The chain
  is a tamper check, not an audit log.
- Require one nested factor inside platform key wrapping on every target, so
  Linux, macOS, and Windows share a single create/unseal path. The factor is
  modelled as `UnsealFactor`/`NestedFactorKind` with an Argon2id password as
  the first variant; a variant qualifies only if it derives its key from a
  hash or symmetric primitive, since TPM 2.0 and the Secure Enclave both wrap
  with P-256.
- Expose the native transport through a lightweight Rust `vault-client`
  feature and integrate it as SecretSpec's compiled `factorseal://` provider.
  The consuming SecretSpec CLI or embedding application connects directly and
  uses the `Keyring` interface implemented by the native `VaultClient`; no provider subprocess or
  registration file is involved.
- Generate the Linux systemd user unit from a template so its absolute
  `ExecStart` comes from whichever packager installed the binary, rather than
  a hardcoded prefix that only one install location satisfied.
- Add a Nix package, NixOS module, and virtual-TPM VM test for the Linux user
  service, native socket authorization, persistence, delay inhibition, idle
  lockout, and session-lock shutdown; carry a
  scoped downstream fix for missing Linux TPM authorization sessions in the
  pinned hardware dependency.

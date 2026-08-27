# Changelog

All notable changes to FactorSeal will be documented in this file.

## Unreleased

- Bump the native protocol to version 3 and forward SecretSpec's declared
  project, profile, base directory, and access reason through each provider
  request, supporting contextual audit and approval surfaces without treating
  caller-provided metadata as identity.
- Add bounded project-scoped approval requests, structured SecretSpec
  interaction IDs, and `factorseal approvals`, `approvals --watch`, `approvals
  approve`, and `approvals deny`. Approval requires a vault-signed challenge
  produced after satisfying one configured unlock group. Pending requests stay
  in memory for seven days, with equivalent requests refreshing the same ID.
  Interactive watch mode shows the authenticated provider principal and
  requires an explicit terminal decision, prompting for an unlock-group choice
  only when multiple alternatives exist; approval commands expose no factor
  selection flag. SecretSpec cache addresses are project-derived and checked
  before project grants are accepted.
- Replace the password-plus-biometric boolean with versioned unlock policies:
  comma-separated factors are AND requirements and repeated `--unlock` groups
  are independently hardware-wrapped OR alternatives. Support password,
  biometric-only, and combined groups.
- Add `factorseal seal` so users and scripts can immediately seal the running
  vault through the authenticated local protocol.
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
- Add the Argon2id password factor used by password-containing unlock groups.
  Nested secret factors must derive their keys from hash or symmetric
  primitives, since TPM 2.0 and the Secure Enclave both wrap with P-256.
- Expose the native transport through a lightweight Rust `vault-client`
  feature and implement `factorseal provider` against SecretSpec's typed IPC
  API. The subprocess translates provider operations into cache-only native
  vault requests; its executable is the authenticated principal. Packages ship
  the endpoint in the main binary but do not install its registration file.
- Generate the Linux systemd user unit from a template so its absolute
  `ExecStart` comes from whichever packager installed the binary, rather than
  a hardcoded prefix that only one install location satisfied.
- Add a Nix package, NixOS module, and virtual-TPM VM test for the Linux user
  service, native socket authorization, persistence, delay inhibition, idle
  lockout, and session-lock shutdown; carry a
  scoped downstream fix for missing Linux TPM authorization sessions in the
  pinned hardware dependency.

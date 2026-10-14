# Development and release status

[Back to the project overview](../README.md).

## Build and test

The desktop tray shows the package version beside FactorSeal in its title,
tooltip, and menu heading. Development builds (with debug assertions enabled)
also show the short Git revision, for example `FactorSeal 0.1.0 (dev · abc12345)`.
Development source archives without Git metadata show `(dev)` instead.

The repository uses [devenv](https://devenv.sh/) on Linux:

```console
$ devenv shell -- bash scripts/test-with-dbus.sh cargo test --workspace --all-targets --all-features
$ devenv shell cargo clippy --workspace --all-targets --all-features -- -D warnings
$ devenv shell cargo fmt --all -- --check
```

On macOS and Windows with Rust 1.91 or newer:

```console
$ cargo test --workspace --all-targets --all-features
$ cargo clippy --workspace --all-targets --all-features -- -D warnings
$ cargo fmt --all -- --check
```

To build and check Desktop on Windows from a WSL2 checkout, including its
approval popup, see [Windows Desktop checks from WSL2](../scripts/windows-desktop-check/README.md).

For Apple credential-exchange SDK and Rust interoperability checks on macOS 26+
with Xcode 26+, run `bash scripts/test-apple-exchange.sh`. See the
[Apple test setup](../platform/apple/README.md) for CI artifacts and the separate
signed-app acceptance procedure.

The feature split is intentional:

- `vault-client`: lightweight native IPC protocol and clients;
- `vault-store`: Automerge documents, encrypted envelopes, Turso, and
  `VaultService`;
- `key-protection`: factor nesting and the injectable enclave boundary;
- `vault`: the full desktop service and platform adapters;
- `hardware`, `cli`, and `secretspec-provider`: native enclave adapter, product
  CLI, and SecretSpec endpoint respectively.

CI runs native Linux, macOS, and Windows jobs. Unit tests use deterministic mock
protectors and never weaken production backend selection. The Nix flake also
provides `nixosModules.factorseal` and a NixOS VM test with a virtual TPM.

SecretSpec provider tests exercise every advertised provider method over the
wire, including convention and native addresses, missing values, and rejected
cross-project access. Linux CI also runs upstream transport conformance against
the built Factorseal executable using the SecretSpec revision in `Cargo.toml`:

```console
$ devenv shell -- cargo build -p factorseal --all-features --bins
$ devenv shell -- python3 scripts/test-provider-conformance.py --endpoint target/debug/factorseal
```

The transport profile checks framing, strict wire validation, initialization,
notifications, and connection lifecycle. Upstream's memory-provider operation,
error-fixture, and lifecycle cases are explicitly reported as not applicable;
they require fixture behavior Factorseal does not implement. The NixOS VM test
separately checks installed SecretSpec discovery, approvals, CRUD, project
isolation, and cache expiry. This is not full protocol conformance on every
desktop platform.

The package builders (`packaging/build-unix.sh` and
`packaging/build-windows.ps1`) leave out `secretspec-provider` until the
SecretSpec IPC API is published, so those builds have no SecretSpec endpoint.
The CLI writes SecretSpec's discovery claim, `factorseal.secretspec.json`, only
when built with that feature. It writes it during `factorseal init`, when the
agent starts, and when Desktop starts its vault worker. Without the claim,
SecretSpec cannot find the `factorseal` provider. To test SecretSpec against a
native macOS or Windows build, add the feature to the CLI build, for example on
Windows:

```console
> cargo build --release --no-default-features --features vault,cli,hardware,secretspec-provider,personal-sync-network --bin factorseal
```

The claim is written to SecretSpec's per-user provider directory:
`$XDG_CONFIG_HOME/secretspec/providers.d` (or `~/.config/secretspec/providers.d`)
on Linux, `~/Library/Application Support/SecretSpec/providers.d` on macOS, and
`%APPDATA%\SecretSpec\providers.d` on Windows.

## Release status

The shared core, native transports, lifecycle monitors, CLI, Secret Service,
SecretSpec endpoint, developer package builders, and physical-host acceptance
runners are implemented. Before an MVP release, Factorseal still needs:

- the SecretSpec IPC API published and installed end-to-end conformance on all
  desktop targets;
- signed and notarized release artifacts;
- native lifecycle and physical TPM/Secure Enclave acceptance across the
  release matrix, including Windows prompt and modern Windows Hello behavior;
- independent security review.

The outstanding security checks are tracked in the
[security release gates](../acceptance/security-release-gates.md), including
cross-account transport tests and packaged-build crash recovery and fault
injection. The release-candidate procedures are in
[Physical enclave and lifecycle acceptance](../acceptance/README.md). Passing one
runner proves only that machine and event; it does not approve the release
matrix. On NixOS/Linux, the real-TPM suite can be run with:

```console
$ nix run .#acceptance-linux -- \
    --root /absolute/test/root \
    --password-file /private/file
```

Developer packaging inputs are described in [Packaging](../packaging/README.md).
No platform is considered release-ready merely because the shared Rust core
builds or its unit tests pass.

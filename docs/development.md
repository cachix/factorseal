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

The macOS app bundle comes from `packaging/macos/Factorseal.xcodeproj`. Xcode
runs `cargo build` through `packaging/macos/cargo-build.sh` and then assembles
and signs the bundle. See [packaging](../packaging/README.md#macos-builds).

For Apple credential-exchange SDK and Rust interoperability checks on macOS 26+
with Xcode 26+, run `bash scripts/test-apple-exchange.sh`. See the
[Apple test setup](../platform/macos/credential-exchange/README.md) for CI artifacts and the separate
signed-app acceptance procedure.

The feature split is intentional:

- `vault-client`: lightweight native IPC protocol and clients;
- `vault-store`: Automerge documents, encrypted envelopes, Turso, and
  `VaultService`;
- `key-protection`: factor nesting and the injectable enclave boundary;
- `personal-sync-iroh`: the iroh courier and pairing manager in the host's own
  process, without the sandboxed network helper that `personal-sync-network`
  adds for Desktop;
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

## D-Bus dependency migration (DEP-7)

Factorseal and Desktop depend directly on zbus 6. Secret Service,
NetworkManager, logind, provider transport, and desktop keyring probes use its
async API and integrated wire types. Synchronous entry points drive complete
operations with `zbus::block_on`; caller identity lookup keeps that runtime on
its dedicated thread so async embedders do not enter a nested Tokio runtime.
The desktop activation poll uses an async timer, and test services run on a
runtime that remains active between synchronous probes.

The shared ashpd 0.13.13 dependency now uses a pinned backport of the
[zbus 6 migration](https://github.com/bilelmoussaoui/ashpd/pull/491) in
`domenkozar/ashpd`. Desktop's settings watcher, GPUI's portals, and oo7's
Secret portal all use that source. The backport retains the stable 0.13.13
API and compatibility fixes while the upstream migration targets main.
The `async-io` feature now selects zbus's built-in runtime; it remains usable
from GPUI's background executor. Its native I/O requires rustix 1.1.5, which
is also selected in the fuzz lockfile.

Stable GPUI CE 0.3 uses oo7 0.6 with zbus 5. The previous GPUI and oo7 Git
patches are removed; migrating oo7 to zbus 6 remains separate upstream work.
Desktop does not call GPUI's credential-storage APIs. gpui-tray 0.3 uses zbus 6.
See [GPUI CE integration](gpui-ce.md) for the component compatibility Git pin
and its validation limits.

Desktop still pulls in zbus 5 and the unmaintained standalone `zvariant`,
`zvariant_derive`, and `zbus_names` crates through these locked dependencies:

| Path | Remaining migration |
| --- | --- |
| GPUI CE 0.3 → oo7 0.6 | Complete the upstream oo7 zbus 6 migration before updating GPUI's credential-storage dependency. |
| rfd 0.15.4 → ashpd 0.11.1 | Migrate the older file-dialog portal path. The shared ashpd 0.13.13 path already uses zbus 6. |
| GPUI CE → accesskit_unix 0.22.1 → AT-SPI | Migrate accesskit_atspi_common, atspi-common, atspi-proxies, and zbus-lockstep/XML tooling together. |
| GPUI CE → notify-rust 4.18.0 | Migrate notification calls to zbus 6. |

Use these commands to inspect the remaining paths after each parent upgrade:

```console
$ cargo tree --locked --workspace --target all -i zbus@5.19.0
$ cargo tree --locked --workspace --target all -i zvariant
$ cargo tree --locked --workspace --target all -i zbus_names
$ python3 scripts/check-fuzz-lock.py
```

These dependencies need API migrations, not a forced Cargo version override.
Keep their types within each dependency's API boundary while zbus 5 and 6
coexist. The exact-version exceptions in
`security/dependency-exceptions.toml` retain their existing expiry. Remove the
three exceptions only after the workspace graph no longer contains the
standalone crates. Validate Secret Service/libsecret interoperability,
NetworkManager, lifecycle sealing, portal dialogs, notifications, tray, and
accessibility before completing DEP-7. The fuzz feature does not enable D-Bus,
but shared dependency versions must still match the product lockfile.

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

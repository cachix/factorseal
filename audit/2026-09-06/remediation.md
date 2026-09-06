**Audit remediation — 2026-09-06**

All eight findings in the original report are fixed in the working tree. The original report and reproduction patch describe the pre-fix commit and remain historical evidence.

| Finding | Change | Regression coverage |
| --- | --- | --- |
| A1 | Transfer logical keyring items; merge metadata and values atomically under the adapter gate. Read current index for each operation. Register imported objects when discovered. Convert v1 archives before importing. | Populated destination, keep/replace policies, next write, adapter reload, malformed import, concurrent import/create, encrypted archive conversion, D-Bus search and secret retrieval. |
| A2 | CLI and Desktop share deterministic naming that reserves all original titles before assigning suffixes. | Colliding titles and suffixes; repeat import addresses the same items. |
| A3 | Both export paths read every live inventory page and compare authenticated store revisions before and after collection. Any inventory error or intervening mutation fails export. | Live inventory pagination, partial inventory failure, changed snapshot rejection, actual store revision changes and stability. |
| A4 | Permission lists and waits return byte-budgeted pages; continuations require the same revision. Both clients read all pages. | 33 large, JSON-escaped approval contexts; every page fits wire encoding; wait response fits; stale continuation rejected. |
| A5 | Export response delivery deadline includes record expiry. | Export deadline cannot exceed stored expiry. |
| A6 | Monitor D-Bus unique-name loss, remove owned sessions and objects, and check owner liveness after session registration. | Real private-bus client disconnect releases sessions; existing session limit and ownership tests retained. |
| A7 | Reject password-manager exports that cannot represent the supplied fields or metadata before returning export bytes. | Card CSV rejection, extra URLs, KeePass TOTP rejection, supported Bitwarden card round trip; existing supported-format round trips retained. |
| A8 | Only match existing attributes when replacement is requested. | Duplicate attributes create distinct items with replacement disabled; existing replacement tests retained. |

Verification:

- `cargo test --workspace --all-targets --all-features`: **328 tests passed**, including D-Bus integration on a private session bus. The additional one-test CLI child-process output is already included in the 51 CLI tests and is not counted twice.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: passed.
- `cargo fmt --all -- --check`: passed.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`: passed.
- Nine `--no-default-features` combinations compiled: `vault-client`, `key-protection`, `vault-store`, `vault-store,key-protection`, `vault-client,hardware`, `hardware`, `cli`, `vault`, `vault,cli,hardware`. Minimal configurations retain existing dead-code warnings.
- `git diff --check`: passed.

The private D-Bus command removes the generated address's GUID suffix for child clients to accommodate this environment, as in the original audit. Verification logs are saved alongside this note.

Compatibility: native protocol v12 requires updating the service, CLI, and Desktop together. Newly written native archives use v2. Valid v1 archives remain readable; incomplete legacy keyring archives fail before restore writes. Password-manager formats now explicitly reject unsupported data instead of silently dropping it.

Native Windows/macOS, physical hardware unlock, and interactive GUI acceptance were not verified in this Linux environment. The Windows cross-build limitation documented in the original audit remains.

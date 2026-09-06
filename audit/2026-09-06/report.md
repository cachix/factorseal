**FactorSeal application audit — 2026-09-06**

Reviewed commit: `c9ca725f19ba40aceab495a041a101108c9fc1c6`.

Found **eight actionable defects: two high priority and six medium priority**. Seven have executable reproductions; the eighth follows directly from the desktop export call path. The existing 314 Linux workspace tests pass, but do not cover these cases. Backup/restore correctness needs attention before users rely on this app for recovery.

This is a repository-wide engineering review with Linux automated verification, not an independent cryptographic certification or a completed physical-device acceptance audit. No application source was changed. Reproductions ran against synthetic data in a separate copy of the reviewed commit.

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| A1 | P1 / high | Linux keyring restore loses restored index entries on the next write | Reproduced |
| A2 | P1 / high | Password-manager import maps distinct source items to the same address | Reproduced |
| A3 | P2 / medium | Desktop backup silently omits entries absent from its cached inventory | Source-confirmed |
| A4 | P2 / medium | Valid approval requests make the permission list exceed the IPC limit | Reproduced |
| A5 | P2 / medium | Export responses omit the secret's expiry from their delivery deadline | Reproduced |
| A6 | P2 / medium | Disconnected D-Bus clients retain sessions and exhaust the session limit | Reproduced |
| A7 | P2 / medium | CSV export silently discards card, identity, and other unsupported fields | Reproduced |
| A8 | P2 / medium | Secret Service rejects duplicate attributes even when replacement is disabled | Reproduced |

**A1 — Restore Linux keyring items through the adapter's consistency boundary**

Locations: [generic import handler](/home/domen/dev/factorseal/src/vault/protocol/service.rs:238), [cached index initialization](/home/domen/dev/factorseal/src/vault/secret_service/agent.rs:85), [index mutation](/home/domen/dev/factorseal/src/vault/secret_service/agent.rs:165).

Native archives include `LinuxSecretService` records, including `secret-service-index`. Import writes those records directly through `VaultStore`, while the running adapter continues using the `Index` loaded at startup. Restored items are absent from its searches and registered D-Bus item objects. The next create/update/delete serializes that stale index over the restored one.

The reproduction imports an index and its secret into a fresh running adapter, creates an unrelated item, then reloads the adapter. The restored item is missing from the persisted index, although its value record remains orphaned. A successful import is therefore not sufficient to restore usable keyring data.

There is an additional merge problem with nonempty destinations: keeping the existing singleton index drops references to imported items; replacing it drops references to destination-only items. Generic per-record conflict handling cannot merge this structure correctly.

Fix: import logical keyring items through an adapter-aware transaction that merges metadata and values, updates the live index, and registers the new D-Bus objects. Do not treat the singleton index as an independent user entry. Test both conflict policies against populated destinations, including a write immediately after import and a restart.

Reproduction: `audit_imported_index_must_survive_next_secret_service_write`.

**A2 — Reserve source names before allocating duplicate-name suffixes**

Locations: [CLI import naming](/home/domen/dev/factorseal/src/bin/factorseal/commands.rs:413), [desktop import naming](/home/domen/dev/factorseal/factorseal-desktop/src/runtime.rs:376).

Importing three items titled `A`, `A`, and `A (2)` into an empty vault produces addresses `A`, `A (2)`, and `A (2)`. The first occurrence of each distinct source title bypasses the occupied-name check, even if an earlier generated suffix already claimed that address.

Without replacement, the third item is reported as kept-existing and never imported. With replacement, it overwrites the second imported item. Both CLI and Desktop contain the same algorithm. Retrying imports containing duplicate titles also generates additional suffixed copies instead of consistently identifying the same source items.

Fix: distinguish existing destination conflicts from collisions among entries in the current import. Reserve all original source names before generating suffixes, and assign a unique destination to every distinct source item. Prefer stable source identifiers where the format supplies them.

Reproduction: `audit_import_must_preserve_distinct_source_items` observes two addresses for three source items.

**A3 — Refresh and validate inventory at export time**

Locations: [capturing cached entries](/home/domen/dev/factorseal/factorseal-desktop/src/app.rs:805), [archive export loop](/home/domen/dev/factorseal/factorseal-desktop/src/runtime.rs:287), [inventory failure fallback](/home/domen/dev/factorseal/factorseal-desktop/src/runtime.rs:156).

Desktop captures `contents.entries` from its UI snapshot and exports exactly those entries. It does not list the live vault when the export begins. Entries added by the CLI or another integration while the window stays open are silently absent from a subsequent backup. Selecting the export panel does not refresh that inventory.

An inventory read failure is worse: the unsealed snapshot can contain an empty default inventory plus `contents_error`, but export remains enabled and ignores that error. The empty export loop performs no live requests and can successfully encrypt an empty archive.

Fix: fetch every inventory page from the live service as part of export, fail on any inventory error, and report the exported entry count. For a consistent backup under concurrent writes, bind inventory and values to a stable export snapshot or detect intervening changes. Add tests for external additions and failed inventory loading. This finding was confirmed by tracing source; native GUI reproduction was not performed.

**A4 — Paginate permission responses by serialized size**

Locations: [unbounded aggregation](/home/domen/dev/factorseal/src/vault/protocol/service/state.rs:181), [permission response](/home/domen/dev/factorseal/src/vault/protocol/service.rs:277), [one-MiB response limit](/home/domen/dev/factorseal/src/vault/protocol/wire.rs:837).

`ListPermissions` and the permission-wait response return all pending and granted permissions. The pending count limit of 128 does not ensure they fit the wire limit. Each application context may contain a 32-KiB base directory, plus other fields.

The reproduction submits 33 individually valid cache requests with distinct projects and long absolute base paths. All correctly request authorization, but the manager's subsequent successful `ListPermissions` result fails encoding because it exceeds one MiB. A same-user client needs no prior cache grant to trigger this. Normal accumulation of large granted records can also reach the limit.

The CLI/Desktop cannot retrieve the list needed to display and manage approvals. Sealing clears pending approvals, but does not solve oversized durable permission collections.

Fix: introduce bounded pagination for both list and wait results, preserving the revision contract. Bound actual serialized bytes, and test maximum-size contexts and accumulated durable grants.

Reproduction: `audit_pending_permissions_must_fit_transport`.

**A5 — Apply record expiry to export delivery**

Location: [export response construction](/home/domen/dev/factorseal/src/vault/protocol/service.rs:222). Compare [normal secret reads](/home/domen/dev/factorseal/src/vault/protocol/service/actions.rs:203).

Normal reads tighten `valid_until` with the record's `expires_at`. `ExportVaultEntry` obtains the same `StoredSecret` but only copies its expiry into response metadata. It never tightens the delivery deadline. A response obtained shortly before expiry can therefore be encoded and delivered after the record expires, subject to the longer lease/manager-grant/transport bounds.

The reproduction creates a record expiring at time 150, exports at time 100, and observes a delivery deadline later than the allowed 50 seconds. This is a policy inconsistency in an already-authorized manager operation, not a grant bypass.

Fix: tighten the export deadline with `secret.expires_at` before the completion check and lease refresh. Extend the existing grant/record delivery tests to exports.

Reproduction: `audit_export_must_obey_record_delivery_expiry`.

**A6 — Remove sessions when their D-Bus owner disconnects**

Locations: [session storage and removal](/home/domen/dev/factorseal/src/vault/secret_service.rs:150), [explicit Close handler](/home/domen/dev/factorseal/src/vault/secret_service/interfaces.rs:293).

Sessions are removed only by explicit `Close`. The adapter does not subscribe to owner-disconnection notifications. Closing a client's bus connection without a session Close leaves its session entry and object registered. The reproduction opens a real D-Bus session, closes the client connection, and observes the retained session.

After 1,024 such sessions during one unseal, new sessions fail with `LimitsExceeded` until the vault is sealed. This can result from short-lived/crashed clients as well as deliberate exhaustion. Negotiated session keys also remain resident unnecessarily. The specification requires sessions to close when the client disconnects. [Secret Service session lifecycle](https://specifications.freedesktop.org/secret-service/latest/sessions.html).

Fix: monitor authenticated bus-owner disappearance, remove all that owner's sessions and objects, and account for disconnects racing session registration. Test repeated connections beyond the configured limit with cleanup enabled.

Reproduction: `audit_disconnected_clients_must_release_sessions`.

**A7 — Reject or explicitly disclose lossy password-manager exports**

Locations: [CSV serialization](/home/domen/dev/factorseal/src/transfer.rs:591), [desktop plaintext confirmation](/home/domen/dev/factorseal/factorseal-desktop/src/app.rs:2013).

The CSV writer accepts all `PersonalSecretKind` variants, but emits only login-style columns. Card numbers, security codes, identity fields, custom fields, and additional URLs are omitted. KeePass CSV also drops TOTP seeds. The only export warning concerns plaintext exposure; it does not explain loss of secret data.

The reproduction imports a Bitwarden card with two card fields, exports successfully to 1Password CSV, and imports the result. Both fields are gone. The original vault remains intact, but migration through the advertised format silently loses data.

Fix: validate representability before export. Either preserve unsupported fields in an explicit compatible encoding, reject unsupported items, or require a clear loss confirmation enumerating affected items/fields. Keep native archives as the lossless path.

Reproduction: `audit_card_export_must_not_silently_discard_card_fields`.

**A8 — Honor CreateItem's non-replacement semantics**

Location: [duplicate-attribute rejection](/home/domen/dev/factorseal/src/vault/secret_service/agent.rs:142).

`create_or_replace` returns an error whenever matching attributes exist and `replace` is false. Clients should be able to create a separate item in this case. Empty attribute maps make this particularly easy to hit: creating a second unrelated item fails. The specification describes replacement as optional, controlled by this flag. [Secret Service CreateItem](https://specifications.freedesktop.org/secret-service/latest-single/#org.freedesktop.Secret.Collection.CreateItem).

Fix: search for a replacement only when requested; otherwise generate a fresh ID and append an item. Update `created`, creation timestamps, and D-Bus registration consistently. Merely removing the error branch is insufficient because later code still replaces the existing index position.

Reproduction: `audit_create_without_replace_allows_duplicate_attributes`.

**Verification and coverage**

| Area | Work performed | Result / limit |
| --- | --- | --- |
| Workspace | `cargo test --workspace --all-targets --all-features` on Linux | 314 passed; includes Desktop unit tests, not interactive GUI execution |
| Static checks | Workspace formatting and Clippy with `-D warnings` | Passed |
| Feature combinations | All nine combinations listed in Linux CI | Passed |
| Shell packaging | ShellCheck for Unix packaging helpers and Linux/macOS acceptance runners | Passed |
| Dependency policy | Current RustSec check using cargo-audit 0.22.2; four policy unit tests | Passed; six exact unmaintained-crate exceptions expire 2026-10-05 |
| Targeted audit cases | Six library negative tests and one CLI negative test in a separate checkout | All seven failed at the intended assertions, reproducing the defects |
| Windows cross-check | Workspace/all-targets/all-features check attempted | Blocked in Turso build script: `rc.exe` absent and `ProgramFiles(x86)` unset; not attributed to app source |
| Crypto and storage | Reviewed factor nesting, key wrapping, AEAD/signature boundaries, authenticated commits, migrations, leases and shutdown; ran existing regressions | No additional confirmed crypto/storage-boundary defect beyond A5; no cryptographic certification |
| IPC and integrations | Reviewed Unix/Windows authentication, framing, approvals, SecretSpec provider, Linux Secret Service and desktop-worker handoff | Findings A1, A4, A5, A6, A8; Windows/macOS native execution remains unverified |
| Desktop and transfer | Reviewed setup/unlock/seal, secret input, inventory, settings, import/export and single-instance handling | Findings A2, A3, A7; visual, accessibility and native input-method acceptance not run |
| Release and hardware | Reviewed CI, packaging, native adapters and acceptance instructions | No packages deployed; no physical TPM/SEP/Hello, suspend/logout, two-account or signed-package acceptance performed |

The first test invocation failed because its isolated D-Bus address advertised a GUID different from the handshake GUID. Repeating with only that address's `guid` component removed passed. This was a test-environment adjustment, not a source fix. The untouched original suite and all defect reproductions are distinguished in the saved logs.

The test configuration deliberately lowers some password-KDF costs. Passing tests do not establish production unlock latency or physical hardware behavior. Existing documented limitations—including same-user injection, whole-directory rollback, logical deletion, platform acceptance and FIPS validation—remain limitations, not newly discovered vulnerabilities. Release requirements are in [the existing security gates](/home/domen/dev/factorseal/acceptance/security-release-gates.md:1).

**Evidence and next steps**

The [reproduction patch](/home/domen/dev/factorseal/audit/2026-09-06/reproductions.patch) adds only the seven negative tests. Apply it to a disposable copy of the reviewed commit, then run the library and CLI separately because Cargo stops after a failing test target:

```sh
devenv shell -- cargo test -p factorseal --lib --all-features audit_ -- --nocapture
devenv shell -- cargo test -p factorseal --bin factorseal --all-features audit_ -- --nocapture
```

The library session-disconnection test requires a reachable isolated D-Bus session. Use the repository's `dbus-run-session` CI setup; the GUID workaround above was specific to this environment. The audit copy used here is `/tmp/factorseal-audit.qGAgP7` and may be removed by normal temporary-directory cleanup.

Saved evidence: [negative-test results](/home/domen/dev/factorseal/audit/2026-09-06/reproduction-results.txt), [workspace, feature and Windows-check logs](/home/domen/dev/factorseal/audit/2026-09-06/verification.txt).

Fix A1–A3 first because they undermine backup and migration correctness. Then address the approval/session availability defects and export expiry, complete interchange conformance, and run the existing native release gates on each supported platform. No fixes, commits, external reports or deployment were performed as part of this audit.

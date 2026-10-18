# Changelog

All notable changes to FactorSeal will be documented in this file.

## Unreleased

- Add a one-time password to a Desktop item from its QR code.
  Scan the code on screen, drop an image of it anywhere in the
  vault, or press Ctrl+V (Cmd+V on macOS) with a copied screenshot,
  image file or setup link. Desktop reads the code locally, adds it
  to the open item or the item with the same name, or starts a new
  login named after it with the username filled in. It finds
  light-on-dark and small blurry codes, never replaces a one-time
  password without saying so, and removes the QR code or setup link
  from the clipboard and deletes its screen capture once read. Setup
  keys that cannot make a code are rejected, and keys are saved
  without spaces, padding or lowercase letters so they export to
  other password managers.

- Add a website's one-time password from the FactorSeal browser
  extension. Choose Add one-time password while the site shows its
  QR code. The extension sends only that tab's picture to Desktop,
  which reads the code and asks which login for the site gets it.

- Show a FactorSeal button inside website login fields. Click it to
  choose a login in Desktop, instead of Desktop opening by itself
  whenever a login form appears. After you sign in, the page asks
  whether to save the login, and Desktop opens only if you choose
  Save.

- Show website icons in Desktop's item list, search results and item pages,
  like Bitwarden. Desktop asks DuckDuckGo's icon service by website name
  through the sandboxed network helper, which also decodes the image. Icons
  stay in memory only while the vault is unsealed. Turn them off with Show
  website icons in Settings, Appearance.

- Show Desktop's unsealed vault as one window-height sidebar, a list column
  and a detail pane, without the header, page title, outer card and footer
  around them. The sidebar holds search, the secret types, Devices, Transfer
  credentials, Back up vault and Settings, with the seal status and Seal at
  its foot. Settings, Transfer credentials, Back up vault and Devices list
  their sections in the same middle column as the secret types. Item fields
  are label and value rows whose actions show on hover or keyboard focus, so
  a whole login fits in a 720-pixel-high window.

- Show one vault pane at a time in narrow Desktop windows. Below 720 px the
  vault shows the sidebar, the list or the open item, with a Back button to
  return.

- Put Desktop text and controls on one size scale. Screens now use five text
  sizes that follow the system or chosen text size, and inputs and the buttons
  beside them share one height. Desktop bundles IBM Plex Sans as a fallback
  when the system font cannot be read or is missing.

- Keep Desktop readable with bundled third-party themes such as One Dark.
  They now follow FactorSeal's own rules for borders, input fields and the
  focus ring. Text, links and button labels keep a contrast of at least
  4.5:1, and borders stay visible. Colors that already meet this are kept.

- Remember Desktop's window size, position and last open page, and title the
  window FactorSeal. A window saved on a display that is gone opens centered
  at its saved size.

- Make Desktop's vault setup and unlock smoother. The password field is
  focused when the window opens, Enter creates the vault or unlocks it, and
  a button shows or hides the password. Setup errors sit under the field they
  belong to and clear as soon as the password changes. A new vault opens
  right after it is created, through the same unlock steps as any other
  unlock, and the unlock screen says which step is running.

- Explain Desktop's vault errors in one plain sentence that says what to do
  next, with Show details and Copy details for the raw text. The "Vault
  unavailable" and create screens also offer Try again. The desktop worker
  now checks that the vault socket folder is private before the hardware
  unlock, so a shared folder fails at once instead of after the full unlock.
  A lifecycle monitor error no longer repeats "invalid vault protocol
  message:".

- Search every part of the vault from Desktop's search box. Results from all
  categories show in one list, grouped by type, with the matching text
  highlighted. Ctrl+F (Cmd+F on macOS) jumps to the search box, the arrow keys
  and Enter pick a result, and Escape clears the search and then leaves the
  box. The sidebar keeps all its categories while searching.

- Add keyboard shortcuts to Desktop. Ctrl+K (Cmd+K on macOS) opens a palette
  that finds items and runs New login, Back up vault, Settings, Keyboard
  shortcuts and Seal now. The arrow keys and Enter move through and open a
  list, Ctrl+C and Ctrl+Shift+C copy the open login's password and username
  outside text fields, Ctrl+L seals, Escape steps back, and Ctrl+/ shows every
  shortcut.

- Show each personal item in Desktop's list with its type icon, its name in
  bold and its username. The item page has a large title with the icon,
  groups the fields, shows an icon next to each field name, and hides empty
  fields behind Add field, which also adds custom fields. Websites can be
  opened, passwords show their strength while being changed, one-time
  passwords show the current code with a countdown, notes show their line
  breaks, and the page shows when the item was last modified.

- Pin favorite personal items to the top of Desktop's item list with the
  star next to an item's title. The rest of the list, search results and the
  palette are sorted by name. Favorites are the flag items already carry, so
  favorites from Bitwarden, 1Password and other imports show up right away.

- Delete personal items from Desktop. The item page has a Delete button that
  asks first, and a toast offers Undo right after. Every saved edit now shows
  a Saved toast with Undo, and Ctrl+Z and Ctrl+Shift+Z undo and redo saved
  changes on the open item, including a password replaced by Generate.
  Editing a field shows Save and Cancel, and Escape cancels. Custom fields
  can be removed.

- Let Desktop's Generate button make a random password as well as the
  12-word phrase, which many sites reject for its length or for missing
  digits and symbols. Generate now opens a panel to pick Random or Words, the
  length, digits and symbols, with a preview that stays hidden until shown
  and a strength meter. Desktop remembers the last choice. The new vault
  password shows the same strength meter.

- Keep Desktop's Copy button the same width when it turns into Copied, and
  show a small notice after copying that counts down to the 30-second
  clipboard clear.

- Show Desktop's choices for file type and key mode as segmented controls,
  with the selected choice raised. Pick a new item's type from a menu with an
  icon for each type. New items start as Login instead of Other.

- Show the commands in Desktop's help steps in monospace blocks with a copy
  button, and show each category's item count only once, in the sidebar.

- Show this device first in Desktop's Devices list, with a Rename button until
  it is paired, instead of an empty list until a second device joins. Pairing
  opens in a sheet with a centered QR, a live countdown until the code
  expires and a single Cancel button. The text now says pairing code
  everywhere.

- Show who is asking in Desktop's approval popup. Apps are named by their
  full path, and the reason passed with `--reason` shows as text from the
  app. The popup names the profile once, scrolls the technical details
  instead of clipping them, and says when the app stopped waiting instead of
  closing.

- Patch quinn-proto to 0.11.18 for three denial-of-service advisories. Review the
  five exact-version maintenance exceptions against the current advisory database
  and renew them until 2026-11-12 while their parent migrations remain tracked.
  Keep vulnerability findings fatal. Preserve the Rust 1.91 atomic API while
  allowing its compatibility alias's deprecation on newer compilers.

- Wait for permission revisions in Desktop instead of reloading the encrypted
  permission inventory twice per second. Wake for permission expiry and discard
  results superseded by a seal, unlock, or refresh.

- Keep one current encrypted snapshot per document in Turso and authenticate the
  complete current inventory with one device-signed manifest. Replace snapshots,
  document heads, and the manifest atomically; unlock verifies only current state.
  Authenticate every retained legacy generation before migrating to schema v6.
  Repack once during migration when at least 64 MiB and half the file are unused,
  with authenticated retry state if interrupted. Preserve encrypted change and
  personal replication histories. Unchanged pairing commands no longer write.

- Compress debug sections in Linux Nix release binaries with zlib. Retain source
  locations in diagnostic backtraces while reducing the bytes read to authenticate
  Desktop, the CLI, and helper executables.

- Let SecretSpec 0.21 and later pass `FACTORSEAL_ROOT` and
  `FACTORSEAL_SOCKET` to the provider. Those releases start a provider with
  only a fixed base environment plus the variables its discovery claim lists,
  so the provider silently used the default vault. The claim now lists both;
  earlier SecretSpec releases ignore the field.

- Tell SecretSpec that approval is needed when a person has not finished
  approving a request within SecretSpec's 30-second operation limit. The
  provider now answers `interaction_required` with the pending permission's
  reference just before the deadline, instead of timing out with
  `deadline_exceeded`. The permission stays pending, so rerunning after
  approving it succeeds.

- Keep permission requests that are waiting for review when the vault seals.
  Pending permissions are now stored in the encrypted vault, local to the
  device, and stay pending after the next unseal, even after Desktop
  restarts. Desktop offers a request again when the app asks again. A request
  denied while the vault is sealed is denied as soon as it is unsealed.

- Flash Desktop's taskbar button on Windows when the approval popup loses
  the foreground before it was clicked, as when Windows gives it the focus
  for a moment and then hands it back to the app being used. A popup opened
  while the main window is active has no taskbar button of its own, so the
  main window's button flashes for it until the popup is in front.

- Unlock on Windows without administrator rights. Windows gives the TPM
  storage hierarchy authorization only to administrators, so `hardwareseal`
  now tries the empty authorization Windows sets by default when it is
  refused, and derives the same storage key, so existing vaults keep working.
  If the TPM rejects that, the error says to run as administrator instead of
  showing a raw TBS status.

- Open Desktop's permission approval popup on macOS and Windows as well as
  Linux, for native SecretSpec requests and requests relayed from WSL2.
  Relayed requests show the WSL distro and that access expires after five
  minutes. The popup no longer takes typing until clicked, and ignores
  approval for one second after its requests change, so keystrokes or an
  Enter meant for another app cannot approve a request.

- Update the SecretSpec provider integration to IPC 0.20, accept the registered
  `factorseal://` provider URI, and display conventional secret names with
  project and profile coordinates. Group related access requests in the
  Desktop review dialog by project and profile, put secret names first under a
  project title, and offer access duration before unlock with a one-hour default.

- Connect Desktop's Devices panel to iroh pairing and encrypted sync. Show QR
  tickets, comparison codes, explicit approval/cancellation, enrolled devices,
  reachability and publication/conflict counts. Keep forwarding while sealed
  while Desktop remains open. Use inherited private control pipes for enrollment
  and vault publication/application; ordinary application IPC is unchanged.
  Install the CLI and Desktop together.

- Add durable personal-device pairing management: compact QR invitations,
  signed requests with matching verification codes, explicit exact-request
  approval, cancellation and controller-pinned membership. Preserve pending
  pairing across restarts and republish personal histories on enrollment.
  Desktop supplies the pairing route and Devices UI.

- Add an optional iroh ciphertext courier and controller-signed membership
  chains, with separate reader and storage-only endpoint authorization. Verify
  forwarding through a restarted storage node after the sender disconnects.
  Desktop owns the background transport after sync setup.

- Use per-item Automerge documents for personal-secret replication. Preserve
  concurrent values and edit/delete conflicts, resolve against observed heads,
  and retain Automerge history across local snapshot projection. This history
  includes old secret values; pruning is not implemented. Upgrade stable-ID
  records and legacy deletion markers without changing device-specific data.
- Connect experimental encrypted sync packets to the vault worker: protect
  reader seeds under the installation root, persist exact outgoing packets
  before spool delivery, and atomically apply received Automerge changes with
  durable receipts. Storage/forwarding needs no reader keys. Host-management
  APIs enforce the unseal lease; Desktop presents pairing and device status.
  Personal documents use format v5 and native IPC uses v14; update the service,
  CLI, and Desktop together. The old experimental revision-packet suite is
  rejected; packets now carry native Automerge changes.
- Keep Secret Service search metadata encrypted. Sealed searches return
  `IsLocked` immediately and require manual Desktop unlock before lookup.
- Store root/index, signing, document, password-derived and archive keys in
  locked pages with guard pages; wipe before release and fail on lock errors.
  Exclude Linux key mappings from dumps and wipe them in fork children. Suppress
  Windows WER heap collection. Document remaining plaintext and native-test limits
  in `acceptance/memory-hardening.md`.
- Extend locked storage to retained CLI/Desktop passwords, secret editor text,
  wire values, store responses, archive payloads, and bounded IPC frames. Fail
  edits/operations on lock exhaustion; preserve existing base64/wire formats.
  `WireSecret::new` is now fallible and request/response `encode` returns
  `LockedBytes`. Large archives require a sufficient OS memory-lock quota.

The current formats are metadata v8, database schema v6, snapshot envelope v7,
current-state manifest v6, document v3 (personal documents v5), record v2, and
native protocol v17. Database schemas v3 and v5 are authenticated and migrated
transactionally after unseal. The v3 conversion projects current document heads
into the record/history envelope and rotates document keys. The v5 conversion
verifies the complete legacy protected-commit v6 chain and its retained snapshots
before replacing it with current heads and a signed manifest. Unknown formats
are rejected and never deleted.

- Fix keyring backup/restore with atomic metadata/value imports and v1 archive
  conversion; new archives use v2. Export from live inventory and reject a
  concurrently changed vault. Preserve source items with colliding titles and
  reject password-manager exports that would discard fields or metadata.
- Paginate permission listings within the IPC message budget and bind pages to
  one revision. Honor record expiry during export delivery. Native protocol v12
  requires updating the service, CLI, and Desktop together.
- Release Secret Service sessions when clients disconnect and honor
  `CreateItem(replace=false)` for duplicate attributes. Add regression coverage
  for all eight audit findings.

- Split the installation root from per-document keys: a permanent
  `InstallationId`, a distinct non-replicating Device `VaultId`, a
  hardware-wrapped installation root, and an independently wrapped DEK per
  document.
- Persist every document generation as a fresh-genesis projection under a
  fresh DEK. Deleted and overwritten values are absent from the new snapshot,
  and the current row's wrapped key is replaced in the same
  transaction. Per-change envelopes are no longer written, and one ML-DSA-65
  signature per generation lives in the protected commit, which now records
  its signature algorithm. A rejected mutation is discarded from memory rather
  than left to ride along with the next write, and the vault-owned buffers
  that carry a serialized value are wiped on drop. This is logical deletion,
  not cryptographic erasure: retained wrapped keys and ciphertext can still
  recover earlier values when the installation root is available.
- Record a bounded, value-free change history beside every document: the
  address, operation, time, value version created and replaced, and the
  transport-authenticated caller or service reason. The history is its own
  ciphertext in the document's envelope, under the same key and signed
  commit, so reads never decrypt it and writes append to it instead of
  rebuilding it inside Automerge. Retention is bounded per document kind.
  Expose it as `ListHistory`, `ListProjectHistory`, and `ListCacheHistory`
  under the `List` permission and as `factorseal history --project`; an entry
  made by another application shows a redacted provenance unless the reader
  holds `manage-permissions`. Secret bytes now travel and persist as base64.
- Hardware-wrap only the installation root for each unlock group and derive
  the document-index key from the root, so unsealing needs one hardware
  operation and at most one user verification. The signing seed and document
  keys are root-unwrapped only for the operations that need them.
- Make `factorseal destroy --yes-really-destroy` remove a sealed vault's local
  directory and ask each backend to remove its locally owned keys. Older
  metadata can be removed without unsealing, but retained stateless TPM
  envelopes may remain usable on their original TPM with valid factors.
  Destruction does not revoke backups or guarantee cryptographic erasure.
- Evaluate every candidate grant from one load of the authorization document
  without writing, accept only a kind-wide grant for kind-wide operations,
  prune expired permission registry entries on write, and let revocation
  remove registry entries even after their expired grant records are swept.
  Updating the Linux Secret Service helper atomically replaces its old
  executable-specific grants without rewriting unchanged grants.
- Authenticate the connected Unix server UID and Windows pipe-owner and
  server-process SIDs before sending request bytes. Windows clients request
  identification-only tokens rather than resource-impersonation authority.
- Verify live reads, inventory, mutations, and transactional compaction against
  trusted in-memory document and global heads. Sign eviction deadlines, remove
  public Automerge heads, and seal on storage-integrity failures. Check WAL
  truncation after writes as retention reduction, not erasure.
- Recheck lease, grant, and record expiry after queueing and before response
  delivery. Sealing cancels unsent responses and queued work; native watchdogs
  terminate wedged key owners without deliberately generating a core dump.
- Escape caller-controlled approval text and isolate approval signing in a
  short-lived helper. Wipe caller-owned Argon2, JNI, and WebAuthN secret buffers;
  disable Unix core files and Linux key-owner dumpability.
- Authenticate Linux lifecycle signals and detect tracked session removal.
  Require a transient Secure Enclave key probe before Apple protector use.
- Update ChaCha20 to 0.10.2, add dependency-audit CI, and expand workspace and
  client-only checks. Track outstanding native acceptance, durability tests,
  and independent review in the
  [security release gates](acceptance/security-release-gates.md).
- Replace XChaCha20-Poly1305 vault envelopes with AES-256-GCM
  envelopes and add persisted `default` and `fips` vault profiles. The default
  password KDF is memory-hard Argon2id; `factorseal init --fips` selects
  PBKDF2-HMAC-SHA-256 with 600,000 iterations. Both profiles retain
  AES-256-GCM and ML-DSA-65. Route vault AEAD and PBKDF2 through
  a replaceable provider boundary. The FIPS profile selects standardized
  algorithms but does not claim that the RustCrypto build or Factorseal
  product is FIPS 140-3 validated.
- Forward SecretSpec's declared project, profile, base directory, reason, and
  requested permission duration through each provider request, supporting
  contextual audit and
  approval surfaces without treating caller-provided metadata as identity.
- Add a unified permission lifecycle with structured SecretSpec interaction
  IDs and `factorseal permissions list`, `watch`, `approve`, `deny`, and
  `revoke`. Granting requires a vault-signed challenge
  produced after satisfying one configured unlock group. Pending requests stay
  in memory for seven days, with equivalent requests refreshing the same
  `prm_` ID; approval promotes that ID into durable granted state.
  Interactive watch mode shows the authenticated provider principal and
  requires an explicit terminal decision, prompting for an unlock-group choice
  only when multiple alternatives exist; approval commands expose no factor
  selection flag. Approval prompts let the user accept the app-requested grant
  duration or choose another duration, including `forever`; the signed approval
  binds that choice and the project grant expires accordingly. SecretSpec cache
  addresses are project-derived and checked before project grants are accepted.
  Approval watches now block on a bounded native revision wait instead of
  polling once per second. The local transports serve a bounded number of
  concurrent connections so a watcher cannot prevent providers from creating
  new approval requests.
- Add an owner-bound native permission wait. The Factorseal provider uses it
  internally to complete the original SecretSpec operation after approval,
  without exposing permission-management APIs to SecretSpec.
- Replace the password-plus-biometric boolean with versioned unlock policies:
  comma-separated factors are AND requirements and repeated `--unlock` groups
  are independently hardware-wrapped OR alternatives. Support password,
  biometric-only, and combined groups.
- Add `factorseal seal` so users and scripts can immediately seal the running
  vault through the authenticated local protocol.
- Replace the legacy file format with the per-user Factorseal vault and make
  `factorseal` the sole product CLI.
- Add the per-user vault: embedded Turso persistence, Automerge
  documents, encrypted snapshots authenticated by ML-DSA-65-signed commits,
  scoped grants, bounded leases, and expiration.
- Add authenticated Linux, macOS, and Windows local transports plus native
  developer packaging inputs, a locally signed macOS pkg builder, and CI
  package smoke tests.
- Obtain the vault's nested factor from `--password-file`, an `--askpass`
  helper, or the controlling terminal, and ship askpass helpers with the macOS
  and Windows packages so both can keep unsealing the vault at login without a
  console and without writing the factor to disk. The helpers are interim:
  prompting and asking are planned to move into the vault itself.
- Seal and zeroize the vault from native Linux logind, macOS AppKit, and
  Windows power/session lifecycle notifications; bound IPC frame time as well
  as size so a stalled client cannot hold the vault indefinitely.
- Record the signature algorithm in each protected commit and bind it into
  the signed transcript. Unknown or absent algorithms are refused rather than
  ignored. ML-DSA-65 supplies the vault's device signing identity and protected
  commit signatures.
- Verify signed Turso commit metadata against SQL rows and detect missing
  history, rolled-back heads, a single document rewound behind its newest
  commit, orphaned snapshots, scope tamper, and signature tamper when opening
  the store.
- Re-sign and compact the protected commit chain once it passes a bound,
  down to one commit and one snapshot per document. Every mutation appends a
  whole encrypted document snapshot, so an unpruned chain grew both the
  database and unseal latency without bound in the number of writes. The chain
  is a tamper check, not an audit log.
- Add the password factor used by password-containing unlock groups.
  Nested secret factors must derive their keys from hash or symmetric
  primitives so they do not introduce a separate public-key ciphertext around
  the platform's opaque native sealed-data mechanism.
- Expose the native transport through a lightweight Rust `vault-client`
  feature and implement `factorseal provider` against SecretSpec's typed IPC
  API. The subprocess translates provider operations into cache-only native
  vault requests; its executable is the authenticated principal. Packages ship
  the endpoint in the main binary. For the default vault root, `init` publishes
  the user's provider claim and the agent refreshes it at startup.
- Generate the Linux systemd user unit from a template so its absolute
  `ExecStart` comes from whichever packager installed the binary, rather than
  a hardcoded prefix that only one install location satisfied.
- Add a Nix package, NixOS module, and virtual-TPM VM test for the Linux user
  service, native socket authorization, persistence, delay inhibition, idle
  lockout, and session-lock shutdown. Bundle HardwareSeal's raw TPM 2.0 command
  codec instead of relying on a patched external hardware crate or a dynamic
  TSS library.
- Preserve structured native hardware outcomes through the public vault API:
  unavailable hardware, unsupported policy, cancellation, denial, unavailable
  authorization UI, locked sessions, invalidated credentials, and generic
  hardware failures remain distinguishable without parsing error strings.
- Add `factorseal completions <SHELL>`, which writes a completion script for
  Bash, Elvish, Fish, Nushell, PowerShell, or Zsh to standard output. The
  script asks `factorseal` for suggestions as you type, so completions always
  match the installed binary and cover every command, option, and possible
  value. Path arguments complete files and directories, and internal commands
  stay hidden. Completion answers from the command definition alone: it never
  resolves a vault root, reads vault metadata, or contacts the service.
- Keep the Secret Service name under FactorSeal's control on Linux: when
  another provider still owns `org.freedesktop.secrets` at unseal, the vault
  now takes the name over as soon as that provider releases it or crashes,
  instead of giving up for the rest of the session. The desktop keyring
  activation helper exits with a failure when the Desktop does not publish the
  name in time, so dbus-broker fails waiting clients instead of queuing them
  forever.
- Keep the system keyring available while the vault is sealed on Linux. The
  Desktop now owns `org.freedesktop.secrets` for the whole session and
  bridges to its vault worker over the native socket under an adapter grant
  of its own, so the collection stays registered and reports `Locked` while
  sealed, reads and writes answer `IsLocked`, and `Unlock` returns a prompt
  that raises the unseal window and completes on unseal or dismissal. The
  headless agent keeps serving in-process. On NixOS the Desktop is a
  bus-activated `dev.factorseal.Desktop` user service instead of an XDG
  autostart entry, so dbus-broker starts that instance on demand and systemd
  restarts it if it exits. Instances started with `--no-secret-service`, with
  `FACTORSEAL_DESKTOP_SECRET_SERVICE=0`, or on a non-default `--root` leave
  the bus name to the configured Desktop.

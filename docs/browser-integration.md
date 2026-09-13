# Browser integration design

Status: experimental implementation; see the [build and installation guide](../extensions/browser/README.md).
The sections below retain the broader design; v1 implementation details and
remaining acceptance work are recorded in that guide. The shared extension core
uses dependency-free JavaScript with runtime validation rather than TypeScript.
Desktop IPC uses short signed polling requests rather than a persistent event
stream. Ed25519 verifies profile signatures; authoritative pairing remains in the
encrypted worker store. Pairing-cache contents only control prompt eligibility.

Build a FactorSeal-owned browser extension and versioned protocol. Use the
[ChiPass browser workflow](https://codeberg.org/ChiPass/ChiPass/src/branch/main/docs/topics/BrowserIntegration.adoc)
as a usability reference for pairing, account selection, approval, and visible
connection state. Protocol compatibility with KeePassXC-Browser is not a goal.

## First milestone

Support automatic login-form detection with Desktop-authorized filling:

1. Install the extension and native messaging host.
2. Pair a browser profile through approval in FactorSeal Desktop.
3. Detect a visible login form on the active HTTPS page.
4. If sealed, show Desktop's unseal prompt for that site, then check for matches.
5. Select and approve an account in Desktop, then fill its username and password.
6. Seal or revoke the pairing and verify that subsequent requests fail.

Start with top-level pages and explicit Desktop approval. Unapproved filling,
cross-origin frames, HTTP sites, wildcard URL matching,
password generation, TOTP, and passkeys are subsequent milestones. Firefox and
Chromium are intended targets; their packaging and permission behavior must be
validated separately before claiming support.

## Components and authority

```text
Website form
    ↕
Content script: inspect and fill the selected form
    ↕
Extension background: validate sender and bind requests to browser context
    ↕ native messaging
Rust bridge: bounded framing and authenticated local transport
    ↕
Desktop browser endpoint: available while sealed; coordinates requests
    ↕
Vault worker: matching, authorization, one-shot secret release
```

The existing executable identity check authenticates the bridge. It does not
authenticate a website or distinguish paired browser profiles. Browser access
needs a separate durable pairing identity and worker-enforced policy. Do not
grant the bridge broad personal-keyring read or management authority.

The background component derives the tab, frame, document, and origin context
from browser APIs and validated message senders. Website-provided messages and
DOM attributes are untrusted. No web-accessible endpoint may issue vault requests.
The worker necessarily trusts the authorized extension for browser context; a
compromised browser or extension is outside that origin-attestation boundary.

Pairing must require Desktop approval, prove possession of a profile-specific
credential on reconnect, and support revocation. A connection name is a display
label, not authentication. Specify the handshake, credential storage, session
authentication, and replay handling before implementing secret retrieval. Use
reviewed cryptographic constructions if required, not a new cryptographic scheme.
Persistent extension storage may hold pairing credentials, never vault passwords
or retrieved login secrets.

## Minimal disclosure and fill policy

- Define dedicated operations for pairing, status, listing matching logins,
  retrieving one approved login, and disconnecting. They must not expose generic
  vault reads, exports, grant management, or project/application secrets.
- Match parsed HTTPS origins exactly in the worker, including effective port.
  Subdomains are distinct. Reject opaque and unsupported origins. Additional
  approved origins are explicit per-item policy, not suffix matches.
- List only matching account metadata after authorization. Metadata is also
  sensitive; never send the browser the entire personal inventory.
- Bind approval to the pairing, session, origin, selected item, operation, and
  short lifetime. Bind extension-side delivery to the initiating tab, frame, and
  document. Revalidate after unlock, approval, and immediately before filling.
- Invalidate pending operations on navigation, disconnect, sealing, expiry, or
  revocation. Check authorization at secret release; do not rely only on a check
  made before an asynchronous approval dialog.
- Reject cross-origin form actions in the initial scope and recheck the form at
  fill time. Fill only the selected visible, editable fields. Never submit the
  form automatically.
- Return only selected username/password fields after approval, not the complete
  personal record. Avoid retaining secrets in background state, storage, logs,
  telemetry, or error messages. JavaScript memory cannot promise reliable wiping.

Once filled, the page can read the credential. Origin checks prevent unintended
delivery; they cannot protect a password from malicious scripts on the approved
site. Sealing prevents new releases but cannot recall a credential already sent.

## Protocol and user experience

Use strict versioned messages, bounded lengths, unique request IDs, explicit
response correlation, replay protection, timeouts, and bounded pending work.
Keep native-messaging framing separate from the vault protocol. Extension host
allowlists complement pairing; they do not replace worker authorization.

Show disconnected, unpaired, sealed, awaiting approval, ready, and incompatible
version states distinctly. Route unlock factors only through Desktop. Show the
requesting browser profile, destination origin, and account in approval UI.
Denial and cancellation must finish the pending request without retry loops.

## Implementation sequence and acceptance

1. Specify the pairing/session protocol and browser-specific worker authority.
   Review it against existing `VaultAction`, grants, and personal-record APIs.
2. Implement the narrow worker operations and Rust native-messaging bridge.
3. Add the background component and form-detection/fill content script, with
   Desktop account selection. Request host access for automatic detection with
   a clear explanation; provide per-site controls and manual retry.
4. Add Desktop pairing, approval, revocation, and platform host registration.
5. Exercise the complete workflow on Firefox and Chromium with real packaging.

Required negative cases include forged content-script requests, unpaired and
revoked profiles, replayed requests, malformed/oversized framing, wrong origins
and ports, cross-origin forms/frames, hidden inputs, navigation while approval
is pending, seal/revoke races, bridge restarts, and extension background restarts.
Verify that candidate listing contains no passwords and that the bridge cannot
use generic APIs to bypass browser policy. Inspect logs and persistent extension
storage for secret leakage. Hardware tests and security review remain release
requirements; a successful autofill demonstration is not sufficient.

## Shared IPC implementation plan

### Shared core and browser adapters

Use one TypeScript extension core for form detection, request state, cancellation,
and fill validation; one language-neutral JSON protocol schema with Rust and
TypeScript validation; and one Rust native-host executable per operating system.
Keep the public browser protocol independent of internal `VaultAction` versions.
Browser requests must never contain arbitrary nested vault actions.

Use `runtime.connectNative()` for a bidirectional session. Firefox and Chromium
both support native messaging with length-prefixed JSON over the host's standard
input/output. Chromium registration uses `allowed_origins`; Firefox uses
`allowed_extensions`. Generate browser-specific manifests and host registration
from common packaging inputs. Keep API naming, background lifecycle, permission
requests, and document identity normalization behind small adapters. See
[Chrome native messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
and [Firefox native messaging](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging).

Target Firefox and Chromium first, including separate installation tests for
Chrome and Edge. Safari and sandboxed-browser packaging need separate evaluation;
do not imply that a shared protocol makes their installation paths identical.

### Two local endpoints

The current vault `Status` operation requires an unsealed service, and sealing
removes its endpoint. Introduce a separate per-user, per-vault Desktop browser
endpoint that lives as long as Desktop, including while sealed. Use private Unix
sockets on Linux/macOS and same-user named pipes on Windows, reusing transport
peer verification and server authentication rather than a localhost HTTP server.

The native host may start the installed Desktop through a fixed activation path
and wait for this endpoint with a bounded timeout. Never pass URLs, pairing
credentials, or secrets through process arguments or activation files. The
existing `factorseal-desktop/src/instance.rs` activation signal only brings up
the existing instance; it is not a request transport. Bind connections to a
configured vault identity rather than accepting browser-supplied filesystem paths.

Desktop's endpoint authenticates the bridge and paired profile, rate-limits
requests, and owns pending UI interactions. It does not retain vault keys or
provide generic database access. Desktop's normal private bootstrap pipes carry
unlock factors to the worker. Add dedicated worker operations for browser lookup,
approval, and release; the bridge receives no permission-manager grant.

The initial feature requires Desktop to own the worker. If a standalone
`factorseal agent` owns the vault, return `desktop_required` with actionable UI;
do not start a second owner or silently replace the running agent.

### Pairing and sealed requests

Pair each browser profile independently. Store a profile authentication key in
local extension storage, never browser-synchronized storage. Persist its public
identity and browser permissions in the protected vault after explicit Desktop
approval. Authenticate each connection using a fresh challenge bound to the
protocol version, vault identity, and session; bind subsequent requests to that
session with authenticated sequence numbers. Finalize this handshake and its
standard cryptographic construction in a protocol review before implementation.

Desktop needs a minimal public pairing cache to recognize profiles while sealed.
It contains IDs, public verification material, display labels, and a revision,
but no site index, usernames, or passwords. Treat it as prompt eligibility only:
the worker rechecks authoritative pairing and revocation state after unlock
before lookup or release. A modified or rolled-back cache must never authorize
credential access. Unknown profiles can request explicit pairing, with throttling,
but cannot impersonate an already authorized profile or trigger its normal flow.
The integrity format for this cache is part of the protocol review.

### Messages

Every envelope carries `version`, `session_id`, `request_id`, `sequence`, `type`,
and a strictly validated payload. Initial negotiation precedes session creation.
Use a 64 KiB frame cap, enforce it before allocation, and keep stdout exclusively
for native messages. Bound strings, pending requests, and response sizes. Reject
unsupported versions explicitly; negotiate capabilities for future operations.

| Message | Direction | Purpose |
| --- | --- | --- |
| `hello` / `challenge` / `authenticate` | Both | Version negotiation and fresh paired session |
| `pair.request` / `pair.result` | Both | Desktop-approved profile enrollment |
| `login.detected` | Extension → Desktop | Start one site-bound detection/approval interaction |
| `request.state` | Desktop → extension | `awaiting_unseal`, `matching`, `awaiting_approval`, or `awaiting_context` |
| `context.check` / `context.confirm` | Both | Revalidate the initiating document before release |
| `fill.result` | Desktop → extension | Selected username/password fields for one approved interaction |
| `fill.ack` | Extension → Desktop | Report filled or discarded; never means website login succeeded |
| `request.cancel` | Extension → Desktop | Navigation, form removal, tab close, or explicit cancellation |
| `request.finished` | Desktop → extension | No match, denied, cancelled, expired, sealed, revoked, or error |
| `vault.state` | Desktop → extension | Update status and invalidate stale work |

`login.detected` contains a background-validated origin and a bounded form
descriptor: opaque tab/document/form tokens, page/frame origins, resolved form
action origin, and detected field roles. It contains no page-entered values,
full HTML, cookies, or URL query strings. Browser-local document tokens route
responses; they are not independently attested website identities for the worker.
Use a per-document nonce when a browser lacks a suitable native document ID.

Account titles, candidate IDs, and selection remain in Desktop. There is no
browser-facing list-all or arbitrary-item retrieval operation. The worker gives
the trusted Desktop only matching candidates; after selection it validates a
single-use approval bound to the pairing, session, request, origin, item/version,
lease generation, and deadline. A changed record requires fresh selection.

### Sealed-to-fill state machine

1. Detect a visible form in the active tab of the focused browser window and
   send `login.detected` once. Browser site permissions must already allow this.
2. If sealed, Desktop shows: "Unseal FactorSeal to check for logins for
   example.com." It must not claim a match before decryption. User dismissal
   terminates the request; factors never enter the browser or native host.
3. On successful unseal, recheck pairing and live browser context, then ask the
   worker for exact-origin matches. No match finishes quietly in the browser UI;
   no account-approval dialog appears.
4. For matches, the same Desktop interaction shows the destination and account
   choices. User clicks Fill or Deny. Unlock alone is not permission to release
   a credential whose account was unknown while sealed.
5. Send `context.check` with a fresh nonce. The extension validates document,
   origin, form, and tab selection before confirming. Desktop taking focus for
   its own prompt must not itself cancel the flow; selecting another browser
   tab or navigating does. The extension checks again immediately before fill.
6. The worker checks the current lease and approval, consumes the one-shot
   release, and returns only the selected fields. Desktop and the host relay
   bounded secret-bearing buffers without logging or persistent storage.
7. The extension fills the original form and reports an acknowledgment. It does
   not submit the form or retain a retry copy. Failure requires a fresh request.

Use a five-minute interaction deadline and a five-second context-check
deadline, with one displayed prompt globally, one pending request per document,
and a bounded global queue. Suppress automatic prompts for the rest of a
document after dismissal; offer explicit retry and "Pause on this site" controls.
Coalesce repeated DOM detections. Never promote a stale queued tab into a prompt.

Seal, revoke, navigation, disconnect, timeout, or background restart invalidates
pending approvals. Reconnect creates a fresh session and never replays a prior
fill. The expected sealed → unsealed transition may resume its waiting request;
a later reseal cancels it. Cancellation races cannot recall released secrets,
so final content-script document checks are required even after worker approval.

### Delivery slices

1. **Contract:** schema, shared fixtures, error/state model, origin normalization,
   pairing/cache threat review, and simulated sealed-to-fill tests.
2. **Desktop transport:** authenticated sealed endpoint, fixed activation,
   cancellation, prompt deduplication, and unlock continuation with a mock client.
3. **Worker policy:** browser-specific grants and one-shot release, authoritative
   pairing checks, exact-origin lookup, and grant/lease race tests.
4. **Native host and extension core:** framing, browser adapters, form detection,
   context revalidation, and a full Desktop-approved fill in Firefox and Chromium.
5. **Distribution:** browser IDs/manifests, platform registration and uninstall,
   upgrade compatibility, real-device acceptance, and independent security review.

Run the same protocol fixtures against Rust, TypeScript, and both browser builds.
Add tests for sealed requests with no matching credential, concurrent browsers,
multiple profiles, prompt focus changes, suppressed prompts, forged pairing cache,
and lost acknowledgments. Do not test only the happy-path login form.

Desktop now registers the native host automatically on startup for the bundled
Firefox and Chromium identities. Registration is unconditional; there is no global
disable setting. Pairing, individual profile revocation, and per-fill approval remain.

### Saving website credentials

The shared extension offers a save on login/registration form submission, with
an explicit popup action for completed forms that do not emit submit events.
Only top-level HTTPS, same-origin forms with unambiguous username/password fields
qualify. Matching new-password confirmation fields must agree. Submission is not
proof of successful authentication.

A signed `save` request binds the original origin, document, username, and password.
Desktop retains the bounded request in memory while asking to unseal if necessary.
The worker finds exact-origin, same-username records; unchanged credentials end
without another prompt. Otherwise Desktop explicitly approves creation or selects
one record to update. A single-use worker ticket binds the complete submitted
payload and reviewed record digest. Saving rechecks pairing and rejects stale
records; updates preserve other personal fields and use the normal personal
storage/history path. The extension receives only completion status.

Save review survives submission navigation because it writes captured credentials
for the original site; it never releases a password back to the navigated page.
Tab closure, cancellation, sealing, and deadlines invalidate pending review.
No submitted credentials are stored in extension storage or logged. Rust signed
payload buffers are wiped on drop; JavaScript cannot guarantee memory zeroization.

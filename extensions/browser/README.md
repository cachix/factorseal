# FactorSeal browser extension (experimental)

One dependency-free extension core is packaged for Firefox and Chromium. Desktop
owns pairing, unlock, account selection, and one-time approval. The extension
never receives the personal inventory or vault keys.

## Build and install for development

Build matching CLI, worker helpers, native host, and Desktop binaries:

```sh
devenv shell cargo build --workspace --all-features --bins
devenv shell node extensions/browser/build.mjs
```

Keep `factorseal`, `factorseal-parser`, `factorseal-network`,
`factorseal-browser`, and `factorseal-desktop` together in `target/debug`.
Create a test vault in Desktop before connecting the extension. Use test secrets.
Restart Desktop after installing or rebuilding the native host: executable
identity checks intentionally reject mismatched binaries.

Start the rebuilt Desktop once. Browser integration is always available:
Desktop registers the native host for Firefox, Chrome, Chromium, and Edge in your
user configuration, and refreshes the executable paths on subsequent startups.
No installer, registration command, administrator access, or extension ID copying
is needed. Registration also records the selected vault and Desktop executable,
so the browser can start that Desktop even when it does not inherit shell variables.

### Firefox

Firefox 129+: open `about:debugging#/runtime/this-firefox`, choose Load
Temporary Add-on, and select `dist/firefox/manifest.json`. Temporary add-ons must
be loaded again after restarting Firefox.

### Chromium, Chrome, and Edge

Chromium/Chrome/Edge 137+: open the browser's extensions page, enable developer
mode, and load `dist/chromium` unpacked. Its development ID is fixed by the
manifest public key ([Chrome documentation](https://developer.chrome.com/docs/extensions/reference/manifest/key)).
If you loaded the earlier build, remove it and load this one again, then pair it;
its old path-dependent ID and pairing storage do not carry over. Store publication
will need the store-assigned identity and corresponding native-host allowlist.

Desktop refreshes registration on every startup. There is no global disable
setting. Extension installation and pairing still require the user’s actions.
Individual profiles can be disconnected, requests denied, and sites paused.

When you enter an unlocked vault, Desktop detects supported browser executables
and offers installation instructions for browsers without an identified paired
profile. Settings retains all detected browsers and paired profiles. Pairing is
per profile; a paired browser does not imply every profile is paired or online.
Browser names are signed, self-reported display metadata, not authorization.
Reload extensions paired with an older build to identify their browser names.
Discovery is best effort; portable or sandboxed installations may not be found.

All registered browsers use the vault selected by the most recently started Desktop.
A standalone `factorseal agent` cannot supply Desktop consent; stop it and launch
Desktop for this workflow. For custom development IDs, the manual
`factorseal-browser --install BROWSER --extension-id ID` command remains available;
Desktop startup restores the bundled IDs.

The popup uses the FactorSeal mark and Ink/Paper palette. Before pairing it shows
only **Pair with Desktop**. While a request is pending, it shows Desktop guidance
and Cancel; login and profile controls appear only after pairing approval.

Open the extension popup and choose **Pair with Desktop**. In Desktop, choose
**Unlock & Pair** when sealed, or **Pair browser** when already unsealed.
A successful unlock completes that pairing without another confirmation.
Pairing requests HTTPS site access, then enables login detection automatically
after Desktop approves. If you decline site access, you can enable it later
from the popup. When a visible login form is
detected in the focused browser's active tab, Desktop prompts to unseal if needed,
checks for matching logins, and offers account-specific Fill buttons. No matches
means no fill prompt. Denial suppresses that document until manual retry or reload.

Use **Check this page** to retry, **Pause / resume this site** to control automatic
prompts, or **Disconnect profile** to revoke pairing with Desktop approval. Close
or cancel a request to dismiss it. Browser requests use the same compact approval
window as access grants, including in-dialog unsealing and the Wayland overlay
with a normal dialog fallback. Closing that approval window or pressing Escape
denies the request. The main Desktop window can stay closed.

Submitting a login or registration form offers to save its credentials in Desktop.
If sealed, unlock there first. Desktop offers **Save login**, or an explicit
**Update password** choice for existing logins with the same origin and username.
Unchanged credentials are skipped. Updates preserve the item's other fields and
reject records changed since review. A save survives the submission's navigation;
closing the tab, canceling, expiry, or sealing cancels pending review. Submission
does not prove that login or registration succeeded.

For pages that do not emit a standard form submission, choose **Save login from
this page** in the popup while the completed form is still visible. Captured
credentials are kept only in memory during review, never in extension storage.

## Current boundaries

- Filling supports HTTPS top-level forms with exactly one visible password and
  an unambiguous username field. Saving also supports matching password and
  confirmation fields, preferring fields marked `new-password`. Cross-origin
  form actions, frames, form-less widgets, and shadow DOM are excluded.
- Matching uses exact parsed origin, including port. Login records must contain
  `username`, `password`, and URL fields. Imported records with ambiguous field
  mappings fail closed. Filling never submits a form.
- Pairing uses Web Crypto Ed25519 signatures and fresh Desktop sessions. Pairing
  private keys live in local extension storage; they are not browser-synchronized
  and are not hardware protected. This browser channel is not claimed post-quantum.
- The extension remembers pairing completion for its popup only; it grants no
  credential access. Desktop and the worker still validate every request.
- The private public-key cache only controls sealed prompt eligibility. The worker
  checks the protected pairing registry again before lookup, release, and saving.
- Desktop/bridge executable authentication and bounded IPC reuse the vault's
  platform routines. Windows currently checks the server's user SID using the
  existing client routine; Unix also checks the Desktop executable identity.
- The page can read filled credentials. A compromised authorized browser or
  extension is outside the website-origin boundary. JavaScript cannot guarantee
  secret zeroization. No secrets are intentionally logged or persisted in the extension.
- No store publication, signed extension packages, Safari adapter, or sandboxed
  browser installation support is provided here. Native hardware/browser release
  acceptance and independent security review remain required.

## Tests

```sh
devenv shell node --test extensions/browser/*.test.mjs
devenv shell cargo test -p factorseal --all-features browser --lib
```

See [the integration design](../../docs/browser-integration.md) for the broader
plan. The implemented v1 uses short polling RPCs across the Desktop endpoint;
this keeps socket requests bounded while consent is pending.

For separate packages, `FACTORSEAL_DESKTOP_EXECUTABLE` selects the Desktop launcher.
If it is a wrapper, `FACTORSEAL_DESKTOP_IDENTITY` names the actual executable for
Unix peer verification. Desktop finds its native bridge beside
`FACTORSEAL_CLI_EXECUTABLE` when configured. The NixOS desktop module sets these
paths for its packaged wrapper. Chromium requires version 137+ for Web Crypto
Ed25519; Firefox requires 129+.

Desktop Settings also lists cached paired profile fingerprints with Disconnect
buttons, so revocation does not require the original extension. The public cache
is not an authoritative list after manual file tampering or restoration.
See [native acceptance](ACCEPTANCE.md) for the remaining real-browser checks.

Unseal and approval allow five minutes, with a 30-second heartbeat grace for
brief browser scheduling gaps. Final page confirmation stays limited to five
seconds; undelivered credentials are discarded after eight seconds. On Linux,
the native host re-executes without empty loader variables exported by browser
wrappers. Nonempty loader variables remain subject to peer-image authentication.

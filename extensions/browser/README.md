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

Firefox 140+: open `about:debugging#/runtime/this-firefox`, choose Load
Temporary Add-on, and select `dist/firefox/manifest.json`. Temporary add-ons must
be loaded again after restarting Firefox.

### Chromium and Edge

Chromium/Edge 137+: open the browser's extensions page, enable developer mode,
and load `dist/chromium` unpacked. Its development ID is fixed by the manifest
public key ([Chrome documentation](https://developer.chrome.com/docs/extensions/reference/manifest/key)).
An older unpacked installation with a path-dependent ID needs to be removed
and paired again.

### Google Chrome

Desktop registers the official Chrome Web Store item ID for Chrome 137 and
later. To test that identity before publication, open the draft's **Package**
tab, choose **View public key**, and add that public key as the `key` in a
temporary unpacked copy of the Chrome store package. Load the copy in Chrome
and confirm its ID matches the draft. The upload ZIP stays as generated. See
[store packages](#store-packages).

Desktop refreshes registration on every startup. There is no global disable
setting. Extension installation and pairing still require the user’s actions.
Individual profiles can be disconnected, requests denied, and sites paused.

When you enter an unlocked vault, Desktop detects supported browser executables
and shows their extension status below the welcome message. Desktop checks standard
browser profile metadata for the bundled extension IDs, including unpacked Chromium
builds, independently of pairing. “Extension not detected” is best effort: temporary
Firefox add-ons and custom profile locations may not be recorded there. Paired browsers
remain visible even when executable discovery misses them. Settings retains installation
instructions and paired-profile controls. Pairing is
per profile; a paired browser does not imply every profile is paired or online.
Browser names are signed, self-reported display metadata, not authorization.
Firefox shares its browser name only with the optional technical-data permission.
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
Pairing works without granting standing access to any website. The toolbar
popup offers **Fill this page** and **Save login from this page** on HTTPS
pages using temporary access from opening the popup. Choose **Enable detection
on this site** separately for each HTTPS hostname where you want field buttons
and automatic save prompts. Reload the page after granting access.
Choosing it opens Desktop, which prompts to unseal if needed, checks for matching
logins, and offers account-specific Fill buttons. Desktop never opens just because
a page has a login form. Field buttons and page notices are extension pages inside
a closed shadow root, so the website can neither read nor press them.

Use **Fill this page** when a field button is hidden, **Pause / resume this
site** to hide field buttons and save questions on a site, or **Disconnect
profile** to revoke pairing with Desktop approval. Close or cancel a request to
dismiss it. Browser requests use the same compact approval window as access
grants, including in-dialog unsealing and the Wayland overlay with a normal
dialog fallback. Closing that approval window or pressing Escape denies the
request. The main Desktop window can stay closed.

On a site with detection enabled, submitting a login or registration form asks
**Save this login in FactorSeal?** on the page. After navigation, a related page
with detection enabled can show the same question. Choose **Save** to review it
in Desktop and unlock there if needed. **Not now** forgets it, and the question
expires after two minutes. FactorSeal skips logins it just filled. Desktop offers **Save login**,
or an explicit **Update password** choice for existing logins with the same
origin and username. Unchanged credentials are skipped. Updates preserve the
item's other fields and reject records changed since review. A save survives the
submission's navigation; closing the tab, canceling, expiry, or sealing cancels
pending review. Submission does not prove that login or registration succeeded.

For pages that do not emit a standard form submission, choose **Save login from
this page** in the popup while the completed form is still visible. Captured
credentials are kept only in memory during review, never in extension storage.

## Current boundaries

- Filling supports HTTPS top-level forms with exactly one visible password and
  an unambiguous username field. Saving also supports matching password and
  confirmation fields, preferring fields marked `new-password`. Cross-origin
  form actions and submit-button overrides, frames, form-less widgets, and
  shadow DOM are excluded. The browser disables the extension in private windows.
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
- Safari and sandboxed browser installations are outside this release's support.
  Native hardware/browser release acceptance and independent security review
  remain required.

## Store packages

From the repository root, run `node extensions/browser/build.mjs --store` with
Node.js and Python 3 to create both upload ZIPs in `extensions/browser/dist/store`.
The build copies the source files and checked-in artwork directly. The ZIPs use
`manifest.json` at their root. The Chrome ZIP omits the unpacked development key.
Firefox keeps the stable add-on ID `factorseal@factorseal.dev`.

Desktop builds pin the official Chrome Web Store item ID
`dpfkfmddmpbpnkhbmdaaoleiackehgjb` for native host registration and installation
detection in Chrome. Start the matching Desktop build once to register it.
Unpacked Chromium and Edge builds use the development ID. Pairing is per
extension ID and browser profile.

Use the following single purpose for both listings.

> Save and fill website logins with approval in FactorSeal Desktop.

State the Desktop dependency and supported hardware in both listings. A
supported Linux or Windows device needs TPM 2.0. A supported Mac needs a Secure
Enclave. Use the [public privacy policy](https://factorseal.dev/browser-extension/#privacy-policy) for the Chrome dashboard and
include its data disclosures in the listings. Chrome permission justifications
are local Desktop communication (`nativeMessaging`), pairing credentials and
site pause preferences (`storage`), on-demand page access (`activeTab`), and the
top-level form script (`scripting`). Optional HTTPS access enables detection
for a user-approved hostname. For Chrome listing artwork, capture a real
1280 × 800 screenshot of the release extension in use with test credentials.

In Chrome's Test instructions and Firefox's Notes for Reviewers, include the
direct link to the exact matching Desktop installer, supported OS and hardware,
the store extension ID, and the [HTTPS login test page](https://factorseal.dev/browser-test/).
Its form stays on the page and submits no credentials over the network.
Reviewers can use the following steps.

1. Install the pinned Desktop build and start it once to register the native
   messaging host. Create a new test vault on the review device.
2. Install the extension, open its toolbar popup, and choose **Pair with
   Desktop**. Approve the request in Desktop.
3. Open the test page. Enter `review@example.com` and a throwaway password.
   Choose **Save login from this page** and approve the save in Desktop.
4. Reload the test page and choose **Fill this page**. Approve the login in
   Desktop and verify that the extension fills the fields.
5. Enable detection for the test hostname, reload, and verify the field button
   and save prompt. Disconnect the profile from the popup.

Test the actual signed store packages with the matching Desktop installer on
each advertised platform. For a Windows MSIX build, confirm that an ordinary
Chrome or Firefox process can discover the native host registration written by
the installed app. See [native acceptance](ACCEPTANCE.md).

## Privacy policy

The FactorSeal browser extension helps you save and fill website logins with
FactorSeal Desktop on the same device. Pairing sends a browser-profile public
key and signed requests to Desktop. When you ask to fill a login, Desktop
receives the site's HTTPS origin and returns the credentials you approve. When
you ask to save, the username, password, and origin go to Desktop for approval.
The approved login is stored in your encrypted vault. Saved logins follow your
Desktop vault's sync settings, including encrypted device sync if you enable it.

If you grant automatic detection for a site, the extension inspects the
top-level login form. On a user-initiated submission, it can hold the origin
and submitted username and password in browser memory for up to two minutes to
offer a save. The extension sends the values to Desktop when you choose
**Save**. **Not now** discards the offer. You can pause automatic detection on
that site or revoke its host access in your browser's extension settings.

The extension stores its pairing key and state and paused origins in the local
browser profile. Desktop stores approved browser pairings and may display the
browser family. Firefox shares that label only if you grant its optional
technical-data permission. You can disconnect a profile in Desktop or in the
extension. Removing the extension clears its local profile storage. You can
remove saved logins through Desktop.

The extension sends these data to the local FactorSeal Desktop app through
native messaging. It does not send them to FactorSeal, advertisers, or
analytics providers. Desktop's optional crash reporting and issue reporting
are configured separately in Desktop. FactorSeal's handling of browser data
adheres to the
[Chrome Web Store User Data Policy](https://developer.chrome.com/docs/webstore/program-policies/policies#protecting_user_privacy),
including its Limited Use requirements. Report privacy questions through the
[FactorSeal issue tracker](https://github.com/cachix/factorseal/issues). Use the
[private security reporting instructions](../../SECURITY.md) for sensitive reports.

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
Ed25519; Firefox requires 140+ for built-in data consent.

Desktop Settings also lists cached paired profile fingerprints with Disconnect
buttons, so revocation does not require the original extension. The public cache
is not an authoritative list after manual file tampering or restoration.
See [native acceptance](ACCEPTANCE.md) for the remaining real-browser checks.

Unseal and approval allow five minutes, with a 30-second heartbeat grace for
brief browser scheduling gaps. Final page confirmation stays limited to five
seconds; undelivered credentials are discarded after eight seconds. On Linux,
the native host re-executes without empty loader variables exported by browser
wrappers. Nonempty loader variables remain subject to peer-image authentication.

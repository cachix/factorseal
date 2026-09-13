# Native browser acceptance

These checks require installed matching binaries, a physical test vault, and each
supported browser. Automated DOM/protocol tests do not replace this acceptance.

1. Serve `fixtures/login.html` on a controlled HTTPS origin and create a Personal
   Login with that exact origin and test username/password. Build/install using
   the README; verify the extension's profile fingerprint in Desktop when pairing.
2. With the vault sealed, visit the page in the focused browser's active tab.
   Confirm that the compact approval window opens above the current app, names
   the origin, and asks to unseal without claiming a
   match. Unseal, choose the account, and confirm the correct fields are filled
   without submission.
3. Repeat with an origin having no stored login. Unseal must still be offered;
   afterward there must be no fill approval or browser credential response.
4. Deny, press Escape, or close the browser approval window. DOM mutations must not reopen the prompt.
   Explicit retry should work. Pause the site and verify reload stays quiet.
5. While unseal/approval is pending, navigate, close the tab, replace the form,
   switch tabs/windows, reseal, or disconnect the browser. No old request may fill
   a new document. Opening Desktop's own prompt must not falsely count as a tab
   switch.
6. Change a login after selection or revoke its pairing before release. The
   worker must reject release. Disconnect via Desktop Settings without the old
   extension present; reconnecting the revoked profile must fail.
7. Restart the browser, background component, native host, and Desktop separately.
   Pending secret responses must not replay. Stored profile pairing should survive;
   an expired session should require a fresh connection.
8. Exercise two browsers and multiple profiles; consent must never cross sessions.
   Test unsigned requests, oversized frames, another user's endpoint, and a bridge
   executable whose digest does not match the configured executable.
9. Inspect extension storage and diagnostics using test credentials. Only local
   pairing material and paused-site preferences should persist in the extension;
   passwords, filled values, and unlock factors must not appear in logs/storage.
10. Start Desktop twice and verify registration is unchanged; move/rebuild the app
    and verify the next startup refreshes its paths. No commands or extension-ID
    copying should be needed. Old configuration files containing disabled flags must
    not prevent registration or connection. Test first launch before vault creation:
    registration must not create the vault directory.
11. Repeat platform registration, upgrade, and uninstall on Linux, macOS, and
    Windows. Validate Nix wrappers separately. Record browser/OS/build revisions
    and results before making a release-support claim.
12. Submit the login and registration fixtures with new test credentials. Verify
    Desktop names the original origin and username, masks the password, and saves
    only after approval. Confirm the new Personal Login appears without reopening
    Desktop and can subsequently be filled. Repeat unchanged credentials: no save
    prompt or duplicate. Change the password: explicitly update the correct account
    and retain its other fields. Change the record during review: the update must fail.
13. Exercise save navigation, denial, tab closure, pairing revocation, and expiry.
    Check that extension storage contains no submitted credentials. Mismatched
    confirmation, hidden fields, and cross-origin actions must not offer saves.
    Test **Save login from this page** and editing/retrying a failed submission.

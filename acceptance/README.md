# Native hardware and lifecycle acceptance

These are opt-in acceptance runners for **physical** Linux, macOS, and Windows
hosts. They are deliberately not part of normal CI: a virtual TPM, mocks, or a
cloud macOS/Windows VM cannot demonstrate the device's actual TPM/Secure
Enclave policy, user-verification prompt, or operating-system lifecycle path.

## Volunteer quick start

Download and unpack the release archive for your platform, open a terminal in
the unpacked directory, and run one command:

### Linux

```console
./run-acceptance.sh
```

Run it from the desktop session you will lock, not through SSH. Your account
must have access to `/dev/tpmrm0` and an active logind session. A repository
checkout can use `nix run .#acceptance-linux` instead.

### macOS

Use a signed release candidate whose embedded provisioning profile authorizes
its Data Protection Keychain entitlements. CI does not publish an unsigned
macOS package; the runner also rejects unsigned or unprovisioned apps during
preflight.

```console
./run-acceptance.sh
```

Approve the Touch ID/macOS verification dialogs. The default run tests screen
lock. Separate sleep and session-switch results are just as simple:

```console
./run-acceptance.sh --event sleep
./run-acceptance.sh --event switch
```

### Windows

From an ordinary, non-administrator PowerShell window:

```powershell
powershell -ExecutionPolicy Bypass -File .\run-acceptance.ps1
```

Approve the Windows Hello dialogs. Administrator privileges are neither needed
nor recommended.

With no options, the runner finds the bundled Factorseal binary, chooses unique
test and evidence paths, generates a random test-only factor, and destroys the
test vault and native test key after a successful run. It never touches an
existing Factorseal vault. The only manual actions are approving native prompts,
locking and unlocking the session when instructed, and confirming that the
prompts appeared.

At the end it prints one line beginning with `PASS` and the path to a single
`.acceptance.txt` file. Attach only that file to
[the physical-acceptance issue](https://github.com/domenkozar/factorseal/issues/2).
It contains the artifact hash, redacted machine information, and pass/fail
fields—no password, username, vault ID, device-key ID, or test secret.

If the run fails, keep the `.partial.txt` evidence file and report the displayed
error. A generated temporary factor may be retained so the isolated failed test
vault can be cleaned up; do not send that factor file to anyone.

## What the runner verifies

Each runner creates a fresh vault through the release candidate binary. The
macOS and Windows runners request native biometric/user verification at
creation and unseal; Linux validates the TPM plus nested password. They verify:

1. the host identifies as physical (known VM models are rejected, and Linux
   additionally requires `/dev/tpmrm0` while Windows requires a ready TPM);
2. the backend recorded in `factorseal status` is the expected real hardware
   backend (`tpm` on Linux, `windows-tpm` on Windows, or `secure-enclave` on macOS);
3. the sealing invariants underneath the vault, through
   `factorseal hardware-self-test`: that re-sealing under one label leaves an
   earlier envelope openable, that another label cannot open it, and that
   deleting a protector forgets its secrets without deleting another label.
   None is observable from a vault that seals once, and these properties have
   been silently wrong on key-store backends before. The self-test works on
   reserved scratch state and never touches the vault beside it. macOS and
   Windows also run its biometric half, which asks for verification several
   times;
4. the native transport permits an authorized local CLI to put, get, and delete
   an exact-byte value;
5. a real OS lock, sleep, shutdown-preparation, or session event causes the
   live vault process to exit and the socket/pipe to become sealed;
6. the same vault can be unsealed again and recover the stored value.

Run the script from the account that will own the release installation. The
zero-option guided mode is preferred for volunteer testing. Release engineers
can override the binary, root, evidence path, and password file. Supplying a
password file disables automatic cleanup unless `--destroy-after` (or
`-DestroyAfter`) is also supplied, allowing a failed or unusual vault to be
inspected. Never use a production Factorseal root or password.

On success, every runner writes a private evidence record in the current
directory by default. Use `--evidence` on the POSIX runners or `-Evidence` on
Windows to select another absolute path. The record is a line-oriented
`key=value` file with schema
`factorseal-physical-acceptance-v1`; it contains the artifact hash, redacted
hardware/OS identity, observed backend, and individual test outcomes. A failed
or interrupted guided run leaves a `.partial.txt` file so the point
of failure is visible. Neither form contains the vault ID, device key ID,
password, test secret, or username. Never overwrite an existing record.

## Advanced Linux invocation

Use the package-installed binary and ensure the user is in an active logind
session with access to the real TPM. The runner asks you to lock the current
session. It must be invoked from a terminal which survives the lock event.

```console
./run-acceptance.sh \
  --factorseal /path/to/factorseal \
  --root "$HOME/.local/share/factorseal-acceptance" \
  --password-file "$HOME/.config/factorseal-acceptance-password" \
  --evidence "$HOME/factorseal-linux.acceptance.txt"
```

The flake app builds and uses the repository's Nix package with the bundled
HardwareSeal TPM backend. The archive runner prefers its sibling
`bin/factorseal`, then a `factorseal` found on `PATH`.

Also complete one installed-service run with `factorseal-start`, then lock the
same logind session. Record the release-candidate hash, machine TPM model,
distribution/version, firmware version, prompt behavior, and results for lock,
suspend, logout, and shutdown. The NixOS virtual-TPM test is regression
coverage only; it does not replace this protocol.

## Advanced macOS invocation

Run against `/Applications/Factorseal.app/Contents/MacOS/factorseal` on a
physical Secure Enclave-capable Mac. The runner asks you to lock/switch away or
sleep the Mac, then waits for the vault to seal. Separately validate the signed
and notarized app by logging in with its LaunchAgent enabled and confirming the
askpass dialog works without a terminal.

```console
./run-acceptance.sh \
  --factorseal /Applications/Factorseal.app/Contents/MacOS/factorseal \
  --root "$HOME/Library/Application Support/Factorseal-acceptance" \
  --password-file "$HOME/.factorseal-acceptance-password" \
  --event lock \
  --evidence "$HOME/factorseal-macos.acceptance.txt"
```

The archive runner prefers its sibling app bundle, then the app installed in
`/Applications`, then a `factorseal` found on `PATH`.

## Advanced Windows invocation

Run from an interactive, standard-user PowerShell session on a TPM 2.0 machine.
The runner asks you to lock the current session, then waits for the vault
process to exit. It must visibly exercise Windows Hello user verification and
confirm the platform credential reports PRF support. Separately install the
signed release candidate, register the Scheduled Task template, log out/in,
and verify the masked askpass dialog and Windows Hello UX.

```powershell
./run-acceptance.ps1 `
  -Factorseal 'C:\Program Files\Factorseal\factorseal.exe' `
  -Root "$env:LOCALAPPDATA\Factorseal-acceptance" `
  -PasswordFile "$env:USERPROFILE\.factorseal-acceptance-password" `
  -Evidence "$env:USERPROFILE\factorseal-windows.acceptance.txt"
```

## Release evidence

For every supported OS/hardware combination, attach the generated evidence
record, redacted script output, and a completed copy of
[the release acceptance record](results-template.md) to the release approval.
The generated file covers the repeatable core test; the template records
signature verification, installed-service behavior, and the additional
lifecycle events that require separate runs. A pass requires all lifecycle
events named above, a verified real backend, an observed native user-verification
prompt where policy requires one, and a successful re-unseal. Treat a missing
prompt, software fallback, inability to seal, or a failure to re-unseal as a
release blocker.

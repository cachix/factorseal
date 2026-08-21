# Native hardware and lifecycle acceptance

These are opt-in acceptance runners for **physical** Linux, macOS, and Windows
hosts. They are deliberately not part of normal CI: a virtual TPM, mocks, or a
cloud macOS/Windows VM cannot demonstrate the device's actual TPM/Secure
Enclave policy, user-verification prompt, or operating-system lifecycle path.

Each runner creates a fresh vault through the release candidate binary. The
macOS and Windows runners request native biometric/user verification at
creation and unseal; Linux validates the TPM plus nested password. They verify:

1. the backend recorded in `factorseal status` is the expected real hardware
   backend (`tpm`/`tpm-bridge` on Linux and Windows, `secure-enclave` on macOS);
2. the native transport permits an authorized local CLI to put, get, and delete
   an exact-byte value;
3. a real OS lock, sleep, shutdown-preparation, or session event causes the
   live vault process to exit and the socket/pipe to become sealed;
4. the same vault can be unsealed again and recover the stored value.

Run the script from the account that will own the release installation. Pass a
new, absolute `--root` and a private password file (`0600`, regular file). Do
not use a production Factorseal root or password. A successful run leaves the
test vault in place so an operator can inspect it. Add `--destroy-after` only
after recording the result: it invokes the explicit, factor-gated irreversible
`factorseal destroy --yes-really-destroy` command to delete both local data and
native keys.

## Linux

Use the package-installed binary and ensure the user is in an active logind
session with access to the real TPM. The runner asks you to lock the current
session. It must be invoked from a terminal which survives the lock event.

```console
nix run .#acceptance-linux -- \
  --root "$HOME/.local/share/factorseal-acceptance" \
  --password-file "$HOME/.config/factorseal-acceptance-password"
```

The app builds and uses the repository's Nix package, including its TPM
authorization-session patch. To test a separately installed release artifact,
run `acceptance/linux.sh --factorseal /path/to/factorseal` with the same
arguments instead.

Also complete one installed-service run with `factorseal-start`, then lock the
same logind session. Record the release-candidate hash, machine TPM model,
distribution/version, firmware version, prompt behavior, and results for lock,
suspend, logout, and shutdown. The NixOS virtual-TPM test is regression
coverage only; it does not replace this protocol.

## macOS

Run against `/Applications/Factorseal.app/Contents/MacOS/factorseal` on a
physical Secure Enclave-capable Mac. The runner asks you to lock/switch away or
sleep the Mac, then waits for the vault to seal. Separately validate the signed
and notarized app by logging in with its LaunchAgent enabled and confirming the
askpass dialog works without a terminal.

```console
acceptance/macos.sh \
  --factorseal /Applications/Factorseal.app/Contents/MacOS/factorseal \
  --root "$HOME/Library/Application Support/Factorseal-acceptance" \
  --password-file "$HOME/.factorseal-acceptance-password"
```

## Windows

Run from an interactive, standard-user PowerShell session on a TPM 2.0 machine.
The runner asks you to lock the current session, then waits for the vault
process to exit. It must visibly exercise the supported CNG/Windows user
verification policy. Separately install the signed release candidate, register
the Scheduled Task template, log out/in, and verify the masked askpass dialog
and Windows Hello UX.

```powershell
./acceptance/windows.ps1 `
  -Factorseal 'C:\Program Files\Factorseal\factorseal.exe' `
  -Root "$env:LOCALAPPDATA\Factorseal-acceptance" `
  -PasswordFile "$env:USERPROFILE\.factorseal-acceptance-password"
```

## Release evidence

For every supported OS/hardware combination, attach the redacted script output
and a completed copy of [the acceptance record](results-template.md) to the
release approval. A pass requires all lifecycle
events named above, a verified real backend, an observed native user-verification
prompt where policy requires one, and a successful re-unseal. Treat a missing
prompt, software fallback, inability to seal, or a failure to re-unseal as a
release blocker.

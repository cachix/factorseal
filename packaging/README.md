# Packaging

Linux, macOS, and Windows are equal Factorseal targets. The packaging inputs in
this directory contain the identity-ready `factorseal` vault CLI and its
`factorseal provider` SecretSpec endpoint. The endpoint runs from the same
installed binary and connects to the background vault service through the
authenticated native client.

The archive builders are reproducible developer packaging, not a claim that an
artifact is ready to release:

- `build-unix.sh linux` creates a tarball with the binaries, systemd user unit,
  interactive session-agent helper, and one-command physical acceptance runner;
- `build-unix.sh macos` creates a tarball and an unsigned `.pkg`. The app is
  signed locally unless an Apple identity and profile are supplied;
- `build-windows.ps1` creates a ZIP containing the executables, the askpass
  helper, Scheduled Task installer, and one-command physical acceptance runner;
- `build-windows-msix.ps1` creates the CLI-oriented MSIX submitted to the
  Microsoft Store. It installs a `factorseal.exe` execution alias and stays out
  of the Start menu. The Store package intentionally does not install the
  interim PowerShell askpass helper or a login-start task.

SecretSpec cache permissions are granted per project through `factorseal permissions`;
there is no installation-wide provider grant. The endpoint, not the SecretSpec
CLI or embedding application, remains the principal seen by the native vault.
The archives include the endpoint code. `factorseal init` publishes the
minimal `factorseal.secretspec.json` claim automatically, and the agent
refreshes its canonical executable path after packaged upgrades.

The Linux Desktop package additionally installs
`org.freedesktop.secrets.service` in the session-bus activation directory.
Its foreground activation command opens a new Desktop or signals the existing
per-vault instance. The activation helper remains alive until the unsealed
Secret Service owns the name, preventing the bus from treating a successful
handoff to an already-running Desktop as an exited activation process.

Official macOS releases still require installer signing and notarization.
Directly distributed Windows ZIP releases require platform signing credentials;
the Microsoft Store signs an accepted MSIX. Linux release jobs must
build against the supported deployment baseline and publish checksums and
provenance. The Linux binaries dynamically require glibc and D-Bus; they are
not universal static binaries and must not be published from a Nix development
shell whose loader paths point into `/nix/store`. Physical TPM/Secure Enclave
acceptance is separate from archive smoke testing.
Use the release-candidate runners in [`acceptance/`](../acceptance/README.md)
on physical hosts and attach their redacted output to the release approval.

A Windows release build signs `factorseal.exe` with `signtool.exe`, requires an
RFC 3161 timestamp URL, and verifies the resulting Authenticode signature before
packaging it:

```powershell
.\packaging\build-windows.ps1 `
  -SigningCertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567' `
  -TimestampUrl 'https://timestamp.example.invalid'
```

Omitting the certificate deliberately produces an unsigned development archive
and prints a warning. Such an archive can exercise CI packaging but is rejected
by release acceptance. The archive's `install-factorseal-task.ps1` replaces the
task template placeholders with the current SID and extracted directory; its
optional `-Root` parameter provides an isolated installed-service acceptance
vault. It refuses to replace an existing task unless `-Replace` is explicit.

## Microsoft Store MSIX

Reserve the Factorseal product in Partner Center before making a submission.
Copy the exact package identity name, publisher ID, and publisher display name
from **Product identity**, then build on Windows with the Windows 10 or 11 SDK:

```powershell
.\packaging\build-windows-msix.ps1 `
  -IdentityName 'IDENTITY_FROM_PARTNER_CENTER' `
  -Publisher 'PUBLISHER_FROM_PARTNER_CENTER' `
  -PublisherDisplayName 'DISPLAY_NAME_FROM_PARTNER_CENTER'
```

The result is `dist\factorseal-<version>-windows-store-<architecture>.msix`.
Submit that unsigned file to Partner Center; the Store applies its own trusted
signature. Do not use the development identity defaults for a real submission.
Build on native x64 and Arm64 Windows hosts if both architectures are
supported; the builder rejects relabeling a binary for another architecture.

Tagged x64 releases are built by `.github/workflows/release-windows-store.yml`.
Configure these GitHub repository variables with the exact values from Partner
Center before pushing a `v<crate-version>` tag:

- `FACTORSEAL_STORE_IDENTITY_NAME`
- `FACTORSEAL_STORE_PUBLISHER`
- `FACTORSEAL_STORE_PUBLISHER_DISPLAY_NAME`

The workflow refuses development identity values, runs the Windows checks,
builds and unpacks the MSIX, produces a SHA-256 checksum and build-provenance
attestation, saves a 30-day workflow artifact, and attaches both files to a
draft GitHub release. Publishing the draft and submitting its MSIX to Partner
Center remain explicit release decisions.

The same workflow can be run from **Actions → Release Windows Store MSIX → Run
workflow**. The default `development` identity needs no repository variables
and only produces the attested workflow artifact; it never creates a GitHub
release. Select `partner-center` to test the real configured identity. Manual
runs never create or modify a GitHub release in either mode.

For local installation before Store submission, sign the package with a test
certificate whose subject exactly matches `-Publisher`:

```powershell
.\packaging\build-windows-msix.ps1 `
  -Publisher 'CN=Factorseal Development' `
  -SigningCertificateThumbprint '0123456789ABCDEF0123456789ABCDEF01234567'
```

That test certificate must be trusted on the test machine. A locally signed
package is for development only; the release acceptance path is a package
installed from a private Store flight. After installation, open a fresh
terminal and run `factorseal --version`, `factorseal init`, and then
`factorseal agent`. Automatic login startup is deferred until the interim
PowerShell password dialog has been replaced by a native prompt.

For physical macOS testing, provide an Apple Development identity and a
matching profile for `dev.factorseal`:

```console
FACTORSEAL_MACOS_SIGNING_IDENTITY='Apple Development: You (TEAMID)' \
FACTORSEAL_MACOS_PROVISIONING_PROFILE=/private/path/Factorseal.provisionprofile \
devenv shell -- packaging/build-unix.sh macos
```

Set both variables or neither. Without them, the app cannot use Factorseal's
protected Keychain storage or pass physical acceptance. Release distribution
also requires signing the `.pkg` and notarization.

## Obtaining a password factor

The default unlock policy contains a password in addition to its platform key,
so the service needs a way to obtain that password when unsealing. Biometric-only
groups skip this input. Password groups accept three sources, in order:

1. `--password-file`, an explicit private regular file;
2. `--askpass <helper>` (or `FACTORSEAL_ASKPASS`), a helper run with the prompt
   text as its one argument, whose standard output is the factor;
3. the controlling terminal, when there is one.

With none of these available the vault stops with a message naming the missing
source, rather than failing inside a terminal prompt it could never show.

A service started by launchd, a logon task, or a systemd unit has no terminal,
so it must use one of the first two. The askpass helper is preferred: the
secret crosses a pipe and is never written beside the vault it protects. macOS
and Windows packages ship their own helper and pass `--askpass` for exactly
this reason, which is why both can keep unsealing the vault at login.
`factorseal agent` waits for initialization by default: before a vault exists,
the process logs the `factorseal init` instruction and waits. As soon as
initialization creates the vault metadata, the same process continues into the
platform's normal askpass flow on all three desktop platforms.

Linux uses `systemd-ask-password` as its askpass helper. The service publishes
a per-user password request, and the terminal agent run by `factorseal-start`
(or a desktop agent) answers it without staging the password in a file.

The shipped helpers are `factorseal-askpass` inside the macOS app bundle, which
prompts through `osascript`, and `factorseal-askpass.cmd` with its PowerShell
companion on Windows, which shows a masked dialog. Neither has been exercised
on a native host yet.

The macOS and Windows helpers are interim. Prompting and asking are planned to
move into the vault itself, which removes the shell scripts and the pipe the
secret crosses.
Treat `--askpass` as a mechanism that unblocked login start on macOS and
Windows, not as the settled design, and do not build further packaging on top
of it.

## Linux session password

The default Linux workflow uses the TPM and a Factorseal password. The systemd
unit therefore does not persist that password or automatically unseal at login. Install
`factorseal` under `/usr/local/bin`, install the unit under the user unit
search path, and put
`factorseal-start` on `PATH`. systemd requires an absolute `ExecStart`, so
the packaged unit is generated from `factorseal.service.in` for that one
prefix. Unpacking the tarball anywhere else means substituting `@INSTALL_DIR@`
in the shipped template again; leaving the generated unit unchanged makes every
start fail with `status=203/EXEC`. Running the helper starts the service,
attaches systemd's terminal password agent while Factorseal asks for its nested
factor, and then waits for `factorseal.sock`. The password travels through
systemd's agent protocol and the askpass pipe; it is never written to the
runtime directory. Logout, service stop, termination, or the lease deadline
seals the vault.

## NixOS module

The repository flake exports `nixosModules.factorseal`. A minimal system import
is:

```nix
{
  imports = [ factorseal.nixosModules.factorseal ];

  services.factorseal = {
    enable = true;
    users = [ "alice" ];
  };
}
```

Listed users are added to the TPM resource-manager group. The module installs
and enables a global systemd user unit. Before a vault exists, the unit remains
active after logging an instruction to run `factorseal init`; it notices the
new vault and continues automatically once initialization finishes. The default
unlock group then requires an interactive password request.
`factorseal-start` supplies the invoking logind session, answers that request,
and waits for the socket. The module also enables polkit so the unprivileged
vault can obtain logind's default-permitted delay inhibitor before holding
unwrapped keys; without that inhibitor the vault fails closed.

`nix build .#checks.x86_64-linux.nixos-module` runs the installed module in a
NixOS VM with a virtual TPM. It covers initialization, service startup, the
real Unix socket, idle and logind session-lock shutdown, and the delay
inhibitor held while unsealed. Physical TPM, client protocol, persistence,
authorization, and suspend/shutdown acceptance require separate tests.

The Linux user unit intentionally does not use systemd options that create a
filesystem mount namespace. Caller authentication reads the ptrace-gated
`/proc/<SO_PEERCRED pid>/exe` link; a namespaced unprivileged user service
cannot read that link on the tested NixOS baseline. The unit still applies
no-new-privileges, W^X memory, native-architecture, Unix-socket-only, SUID/SGID,
realtime, and restrictive-umask controls. Restoring mount isolation requires a
different verifiable IPC application identity or a broker architecture.

The module has two mutually exclusive host modes. The default
`services.factorseal.mode = "agent"` installs the headless systemd user unit.
For a graphical session, use:

```nix
services.factorseal = {
  enable = true;
  mode = "desktop";
  users = [ "alice" ];
  desktop.autostart = true;
};
```

Desktop mode supplies `org.freedesktop.secrets`. On desktops that enable GNOME
Keyring, explicitly turn off that competing provider so the bus name has one
owner:

```nix
services.gnome.gnome-keyring.enable = lib.mkForce false;
```

Desktop mode installs both packages, exports the exact Desktop executable path
used by `factorseal desktop`, and creates an XDG autostart entry. It does not
install the competing headless user unit or use systemd askpass; the Desktop
process owns password/biometric prompting and, once unsealed, publishes the
same native Factorseal endpoint and Linux Secret Service adapter.

The application launcher, autostart entry, and D-Bus activation record all use
a configured wrapper carrying the CLI executable identity and lease timeouts.
This also works when the session bus has not inherited login-shell variables.
`factorseal desktop` reads the module's timeout environment variables; explicit
`--idle-seconds` and `--maximum-seconds` arguments override those defaults.

Desktop requires Rust 1.97 or newer. On a stable NixOS release with an older
toolchain, keep the Factorseal flake's own Nixpkgs input (do not make it follow
the system's Nixpkgs) and select its packages explicitly:

```nix
services.factorseal.package = factorseal.packages.${pkgs.stdenv.hostPlatform.system}.factorseal;
services.factorseal.desktopPackage = factorseal.packages.${pkgs.stdenv.hostPlatform.system}.factorseal-desktop;
```

The desktop adapter uses `hardwareseal` directly and rejects software fallback.
Linux biometric policies fail closed; Windows biometric policies require a
Windows Hello platform credential with PRF support; macOS biometric policies
use the Data Protection Keychain. Physical-host acceptance remains mandatory
because CI cannot demonstrate the native prompt or hardware boundary.

## Native lifecycle scope

The vault registers native lifecycle monitors on every target: logind lock
state with a delay inhibitor on Linux, Core Graphics lock state plus AppKit
workspace notifications on macOS, and Windows power/session notifications
through a hidden top-level window. The guided physical acceptance runners prove
screen lock and suspend independently, with a recovery unseal between them.
The supplied service definitions also cover logout and orderly stop. Until real
installed artifacts prove the remaining shutdown and logout paths, the packages
remain development artifacts.

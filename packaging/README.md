# Packaging

Linux, macOS, and Windows are equal Factorseal targets. The packaging inputs in
this directory contain the identity-ready `factorseal` vault CLI and its
`factorseal provider` SecretSpec endpoint. The endpoint runs from the same
installed binary and connects to the background vault service through the
authenticated native client.

The archive builders are reproducible developer packaging, not a claim that an
artifact is ready to release:

- `build-unix.sh linux` creates a tarball with the binaries, systemd user unit,
  and interactive session-unseal helper;
- `build-unix.sh macos` creates a tarball and an unsigned `.pkg` containing an
  app bundle, its askpass helper, and a LaunchAgent property list;
- `build-windows.ps1` creates a ZIP containing the executables, the askpass
  helper, and a Scheduled Task template. Selecting a maintained Windows installer toolchain remains a
  release decision; current WiX releases require explicit OSMF terms and are
  not silently accepted by this repository.

SecretSpec cache permissions are granted per project through `factorseal permissions`;
there is no installation-wide provider grant. The endpoint, not the SecretSpec
CLI or embedding application, remains the principal seen by the native vault.
The archives include the endpoint code but do not install a SecretSpec
registration file; packagers or users must register the absolute executable
path as described in the repository README.

Official macOS and Windows releases still require platform signing/notarization
credentials. Linux release jobs must build against the supported deployment
baseline and publish checksums and provenance. The Linux binaries dynamically
requires glibc, D-Bus, and `tpm2-tss`; it is not a universal static binary and
must not be published from a Nix development shell whose loader paths point
into `/nix/store`. Physical TPM/Secure Enclave acceptance is separate from
archive smoke testing.
Use the release-candidate runners in [`acceptance/`](../acceptance/README.md)
on physical hosts and attach their redacted output to the release approval.

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

Listed users are added to the TPM resource-manager group. The module installs a
global systemd user unit but deliberately does not enable it at login, because
the default unlock group requires an interactive password request. `factorseal-start`
supplies the invoking logind session and waits for the socket. The module also
enables polkit so the unprivileged vault can obtain logind's default-permitted
delay inhibitor before holding unwrapped keys; without that inhibitor the vault
fails closed.

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

The pinned `hardware-enclave` 0.2.10 Linux backend omits authorization sessions
from its TPM commands. The Nix package carries the narrow downstream patch in
`nix/patches/hardware-enclave-tpm-auth-sessions.patch`; it wraps each authorized
command in `tss-esapi`'s encrypted null-auth session. Remove the patch when an
equivalent upstream release is pinned. The standalone Linux archive builder
does not patch Cargo dependencies and therefore remains a development artifact
until that fix is consumed upstream or through a repository-wide source pin.

## Native lifecycle scope

The vault registers native lifecycle monitors on every target: logind with a
delay inhibitor on Linux, AppKit workspace notifications on macOS, and Windows
power/session notifications through a hidden top-level window. The supplied
service definitions also cover logout and orderly stop. Until real installed
artifacts prove these paths during suspend, shutdown, logout, and session lock,
the packages remain development artifacts.

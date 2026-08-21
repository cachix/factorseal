# Packaging

Linux, macOS, and Windows are equal Factorseal targets. The packaging inputs in
this directory contain the identity-ready `factorseal` vault CLI. The
built-in `factorseal` provider ships with SecretSpec and connects to the
background vault service through its keyring interface.

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

After device initialization, `factorseal grant-secretspec` authorizes the
exact SecretSpec CLI or embedding application executable that will connect to
the native vault. No provider endpoint or SecretSpec registration file is
installed by Factorseal.

Official macOS and Windows releases still require platform signing/notarization
credentials. Linux release jobs must build against the supported deployment
baseline and publish checksums and provenance. The Linux binaries dynamically
requires glibc, D-Bus, and `tpm2-tss`; it is not a universal static binary and
must not be published from a Nix development shell whose loader paths point
into `/nix/store`. Physical TPM/Secure Enclave acceptance is separate from
archive smoke testing.
Use the release-candidate runners in [`acceptance/`](../acceptance/README.md)
on physical hosts and attach their redacted output to the release approval.

## Obtaining the nested factor

Every vault requires one nested factor in addition to its platform key, so the
vault needs a way to obtain that factor when unsealing. It accepts three sources, in
order:

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

The shipped helpers are `factorseal-askpass` inside the macOS app bundle, which
prompts through `osascript`, and `factorseal-askpass.cmd` with its PowerShell
companion on Windows, which shows a masked dialog. Neither has been exercised
on a native host yet.

These helpers are interim. Prompting and asking are planned to move into the
vault itself, which removes the shell scripts and the pipe the secret crosses.
Treat `--askpass` as a mechanism that unblocked login start on macOS and
Windows, not as the settled design, and do not build further packaging on top
of it.

## Linux session password

The Linux installation requires the TPM and a Factorseal password. The systemd
unit therefore does not persist that password or automatically unseal at login. Install
`factorseal` under `/usr/local/bin`, install the unit under the user unit
search path, and put
`factorseal-start` on `PATH`. systemd requires an absolute `ExecStart`, so
the packaged unit is generated from `factorseal.service.in` for that one
prefix. Unpacking the tarball anywhere else means substituting `@INSTALL_DIR@`
in the shipped template again; leaving the generated unit unchanged makes every
start fail with `status=203/EXEC`. Running the helper prompts
through `systemd-ask-password`, places the password briefly in the user's
private runtime directory, starts the service, waits for `factorseal.sock`, and
removes the runtime file. Logout, service stop, termination, or the lease
deadline seals the vault.

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
each unseal session requires an ephemeral password handoff through
`factorseal-start`. It also enables polkit so the unprivileged vault can
obtain logind's default-permitted delay inhibitor before holding unwrapped
keys; without that inhibitor the vault fails closed.

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

# Spike: WSL2 bridge via interop, not a new transport

## Status

Not yet run. This supersedes the framing (not the findings) of
`spikes/wsl2-hyperv-socket-bridge` and `spikes/wsl2-mirrored-loopback-bridge`.
Those two spikes answered "can bytes cross the VM boundary" and "can we
authenticate the peer that sends them" by building a new transport and a new
application-layer token from scratch. An independent review of this
repository's own `SECURITY.md` found that both spikes were solving a harder
problem than the vault actually requires, and identified a mechanism that
needs no new transport at all. This spike validates that mechanism instead.

## The correction that changes the approach

`SECURITY.md:253-263` already states, for every existing native transport:

> Executable identity is resolved after the connection is accepted, and no
> supported platform reports the image a peer had at connect time... Executable
> grants are defense in depth against the wrong program reaching the vault,
> not a boundary between same-user processes... The boundary the vault does
> enforce is the Unix user or Windows SID.

The prior two spikes (and the design discussion around them) treated
"prove which exact binary is calling" as the security boundary WSL2 breaks.
It was never that boundary, even natively. The boundary that matters —
same Windows SID — is one a WSL2 process can already reach today, with no
bridge at all: WSL2 interop (enabled by default) lets a process inside a
distro execute a Windows `.exe`, which then runs as a genuine Windows
process under the interactive user's own logon session and token. To a
Windows-side peer, that process is indistinguishable from one the user
launched by double-clicking it or running it from PowerShell.

Checked directly against the code rather than taken on faith: `caller_identity()`
in `src/vault/windows.rs:601-639` resolves a connecting peer's SID
(`client_sid`, `src/vault/windows.rs:649`), then its PID, then its on-disk
executable path via `sysinfo`'s generic Windows process introspection
(`process_executable`, `src/vault/windows.rs:690-707`, wrapping
`QueryFullProcessImageNameW`), then hashes that file. None of this is or
could be WSL-aware — it's generic Win32 process introspection keyed only on
PID and SID. An interop-launched `.exe` gets a completely ordinary PID, SID,
and image path once it's running, so this code would authenticate it exactly
as it authenticates any other Windows client, with zero changes.

## The two mechanisms this spike checks

### 1. Interop reverse-connect broker

A process inside WSL2 execs a small Windows `.exe` through interop; that
`.exe` connects out to the existing named-pipe transport as an ordinary
Windows client. Nothing in the transport or authentication layer changes —
this is the existing Windows client path, reached from an unusual place.

What needs checking empirically, not just architecturally: does an
interop-launched process really present the *same* SID, and does its image
path resolve the *same* way, as a natively-launched process? "Should" is not
"does" — this project's whole existing practice has been to run the actual
code rather than trust the docs.

### 2. Launch-time delegation

Instead of a WSL2 process reaching out to Windows, Windows reaches into
WSL2: the Windows agent runs `wsl.exe -d <distro> -- <command>` itself, as
its own child process, and hands the launched process a single-use
capability at launch time rather than authenticating a connection later.
Nothing is attested at connect time because nothing needs to be — the vault
already knows exactly what it just launched, the same way `factorseal
provider`'s endpoint executable is the authenticated principal today
(`SECURITY.md:238-239`).

One thing worth being precise about before building on this: the original
proposal described this as passing the capability "over an inherited fd."
That's not quite the right mental model, and this spike checks what actually
is. `wsl.exe` launches a process inside a *separate kernel* via the LxssManager/
HCS machinery — a literal Windows `HANDLE` or Linux file descriptor cannot be
inherited across that boundary the way it can within one process tree on one
kernel; file descriptors are kernel-local. What genuinely is documented and
routinely relied on (piping into and out of `wsl.exe` from cmd/PowerShell is
a common pattern) is that `wsl.exe`'s own **stdin/stdout/stderr get plumbed
through to the launched process** when the parent redirects them. So the
achievable version of this idea is: Factorseal Desktop spawns `wsl.exe` as
its own child process with stdin/stdout redirected (ordinary
`std::process::Command` redirection, nothing WSL-specific), and the
capability rides over that redirected stdio. This spike checks whether that
actually round-trips end to end, not whether literal fd inheritance is
possible (it isn't).

## What's here

- `src/bin/identity_probe_listener.rs` — Windows-side TCP loopback listener
  that, on connection, reports the peer's PID, SID, and resolved executable
  path using the same techniques `src/vault/windows.rs` uses (not a copy of
  that code — a standalone reimplementation for this throwaway spike, kept
  independent of the product crate). Run it once, then connect to it twice:
  once from a native PowerShell-launched client, once from the same client
  launched via WSL2 interop. The report should be identical in shape and
  differ only in PID/timestamp.
- `src/bin/identity_probe_client.rs` — trivial Windows `.exe` that connects
  to the listener above and sends one message. Built once, run from two
  different places.
- `src/bin/capability_delegator.rs` — Windows program that spawns
  `wsl.exe -d <distro> -- <command>` as its own child process with
  stdin/stdout redirected, writes a random capability to the child's stdin,
  and reads back what the child echoes.
- `capability-receiver` (native Linux binary, built directly in this WSL2
  environment, run inside the distro by the delegator above) — reads its
  own stdin, echoes it back on stdout.

This crate sits outside the main Cargo workspace, same as the other two
spikes, for the same reason: nothing here should affect `factorseal`'s
build, lints, or CI.

## How to run it

### Validating the interop broker (option 1)

**On Windows**, build or copy `identity-probe-listener.exe` and
`identity-probe-client.exe`, then start the listener:

```powershell
.\identity-probe-listener.exe
```

Run the client **natively first**, as a baseline:

```powershell
.\identity-probe-client.exe
```

Note the reported PID, SID, path, and hash, then restart the listener and
run the **same** `identity-probe-client.exe` a second time, this time from
inside WSL2 via interop:

```console
$ /mnt/c/path/to/identity-probe-client.exe
```

Compare the two reports. The SID should be identical both times (same
Windows user); the path and hash should be identical (same file); only the
PID and any timestamp should differ. That's the empirical claim from
`SECURITY.md`'s framing being checked directly: an interop-launched process
is not a special case to this identification logic.

### Validating launch-time delegation (option 2)

**On Windows**, build or copy `capability-delegator.exe`. `capability-receiver`
needs to be built *inside* WSL2 (`cargo build --bin capability-receiver`
from this directory, already done natively above) since it's a Linux binary
`wsl.exe` will execute directly inside the distro — copying a
cross-compiled Windows binary here would defeat the point.

```powershell
.\capability-delegator.exe NixOS /home/<you>/projects/factorseal/spikes/wsl2-interop-bridge/target/debug/capability-receiver
```

Expected: the delegator prints the capability it minted, then "received
back" the same value, then `MATCH`. That confirms a capability handed to a
`wsl.exe`-launched process via redirected stdio survives the round trip with
nothing the launched process needed to discover, connect to, or
authenticate against.

## Non-goals

- No attempt to reuse Factorseal's actual vault wire protocol or named-pipe
  transport code — this only checks whether the *identification* and
  *delegation* mechanics work, the same scope limit the other two spikes
  used for the transport question.
- No grant-model changes (`wsl:<distro>` principals, mandatory Desktop
  approval, short leases) — those are product decisions for the maintainers,
  not something a spike settles.
- Option 3 (Hyper-V Sockets with a host-assigned VM identity) and Option 4
  (the WSL Plugin API as an external witness) are deliberately out of scope
  here per direction: both need privilege escalation work to investigate
  properly, and are postponed rather than pursued now.

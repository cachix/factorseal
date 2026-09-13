# Spike: WSL2 to Windows host IPC over Hyper-V Sockets

## Status

**Confirmed working.** Throwaway validation code — nothing here is wired
into `factorseal`, and none of it should be imported by product crates. It
exists to answer one narrow question before any real design work starts:

> Can a process inside a WSL2 distro open a byte-stream connection to a
> listener on its Windows host without a virtual network, a TCP port, or a
> kernel module the user has to install by hand?

Yes, with one caveat. `wsl-client` connected to `windows-listener.exe` and
completed a full round trip (`sent: hello from wsl2` /
`received: windows-host-echo: hello from wsl2`) once the listener was bound
to the WSL2 utility VM's actual ID rather than the `HV_GUID_CHILDREN`
wildcard — see "One-time setup" and "Open problem this spike surfaced"
below for why that's a caveat worth taking seriously, not a footnote.

## Why this question matters

Factorseal's Windows desktop app seals secrets through TPM 2.0 (via TBS) and
unwraps them with Windows Hello's PRF extension. Both require native Windows
APIs that do not exist inside a WSL2 guest: there is no `/dev/tpmrm0`, and
there is no bridge from the WSL2 kernel to Windows' TBS or WebAuthn platform
authenticator. A WSL2 build of Factorseal can therefore never do its own
sealing; at best it can be a thin client that forwards vault requests to the
real Windows service running on the host, which does the actual hardware
ceremony.

That only works if there's a practical transport across the VM boundary that
doesn't regress the trust model the native transports already rely on (see
`docs/architecture.md`, "Linux uses a private Unix socket, `SO_PEERCRED`... /
Windows uses a same-user named pipe, client impersonation, SID and PID"). A
loopback TCP port is reachable by anything in the WSL2 distro and carries no
peer identity at all. Hyper-V Sockets (`AF_HYPERV` on Windows, `AF_VSOCK` on
Linux) are the transport Microsoft itself uses for WSL2's own plumbing
(`\\wsl$`, WSLg's Wayland/audio channels) — not reachable over any network
interface, and not dependent on the WSL2 virtual network stack being up.

This spike only tests the transport. It does not attempt authentication,
framing, or anything resembling the real vault protocol — see "Non-goals"
below.

## What's here

- `src/bin/windows_listener.rs` — binds `AF_HYPERV` on the Windows host,
  accepts one connection, echoes back whatever it reads with a fixed prefix,
  then exits. Takes the target VM's ID as an optional first argument (see
  "One-time setup" below for why this is required for WSL2, not optional in
  practice). Windows-only; compiles to a no-op on other targets.
- `src/bin/wsl_client.rs` — connects from inside WSL2 over `AF_VSOCK` to
  `VMADDR_CID_HOST`, sends one message, prints the echo, then exits.
  Linux-only; compiles to a no-op on other targets.

Both sides agree on a single `u32` port (`PORT` constant, currently
`0x0000_5A17`, duplicated in both files since a shared crate isn't worth it
for one constant). The Windows side turns that port into a Hyper-V Sockets
`ServiceId` GUID using Microsoft's well-known port-compatibility template
(`xxxxxxxx-FACB-11E6-BD58-64006A7986D3`, `HV_GUID_VSOCK_TEMPLATE` in
`hvsocket.h`); the Linux `AF_VSOCK` transport does that same translation
internally, so the Linux side just uses the port directly.

`windows-rs` 0.61's win32metadata does not carry `hvsocket.h` at all — it
exposes only the bare `AF_HYPERV` constant, not `SOCKADDR_HV` or the
`HV_GUID_*` well-known GUIDs. `windows_listener.rs` hand-defines those from
[the public Windows 10 SDK header](https://github.com/tpn/winsdk-10/blob/master/Include/10.0.16299.0/shared/hvsocket.h),
cross-checked against Microsoft Learn's "Make your own integration services"
guide. The Windows binary was cross-compiled and linked for real with
`cargo xwin build --target x86_64-pc-windows-msvc` from WSL2 (this repo's
`devenv.nix` already provides `cargo-xwin` and the MSVC target), producing a
valid PE32+ executable — so the WinSock API usage type-checks and links
against the real Windows import libraries. What that build can't validate is
runtime behavior: whether `HV_GUID_CHILDREN` actually matches what the
current Windows Hyper-V platform driver expects. That can only be confirmed
by running it.

This crate deliberately sits outside the main Cargo workspace (own
`[workspace]` table, not listed in the root `Cargo.toml` members) so it can't
affect `factorseal`'s build, lints, or CI, and so nobody mistakes it for
product code.

## One-time setup on the Windows host

Hyper-V Sockets require every `ServiceId` a host application uses to be
registered before connections are permitted — Microsoft's guide states this
unconditionally ("In order to use Hyper-V sockets, the application must be
registered with the Hyper-V Host's registry"), and it holds in both
directions: this spike originally assumed registration was only needed when
the *host* connects out to a *guest* listener, and that assumption was wrong.

Register this spike's `ServiceId` (the port-template GUID for `PORT =
0x00005A17`) in an elevated PowerShell:

```powershell
$serviceId = "00005a17-facb-11e6-bd58-64006a7986d3"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices" -Name $serviceId -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\$serviceId" -Name "ElementName" -Value "wsl2-hyperv-socket-bridge-spike"
```

Registration alone was not enough to get a WSL2 guest connecting to accept —
see [microsoft/WSL#5751](https://github.com/microsoft/WSL/issues/5751):
binding the listener's `VmId` to the wildcard `HV_GUID_CHILDREN` (correct for
a regular Hyper-V VM per Microsoft's own guide) silently does not accept
connections from a WSL2 guest specifically. The documented workaround is to
bind to the WSL2 utility VM's *actual* VM ID instead. Find it with an
elevated PowerShell while the distro is running:

```powershell
hcsdiag list
```

This lists running Host Compute System instances; the one for your distro
shows a GUID next to its name. That GUID changes every time WSL2's utility VM
restarts (`wsl --shutdown`, host reboot, or the first `wsl` launch after
either), so this is a per-session value, not a one-time constant like the
`ServiceId` above.

## How to run it

**On the Windows host** (needs Rust 1.91+; matches `docs/development.md`):

```powershell
cargo run --bin windows-listener -- <VM-ID-from-hcsdiag>
```

It prints a line when it starts listening, then blocks until a client
connects. Running it with no argument falls back to `HV_GUID_CHILDREN` and
prints a warning — per the issue above, that fallback is expected not to work
against a WSL2 guest, and is kept only because it's the technically-documented
default for non-WSL2 Hyper-V VMs.

**Inside WSL2**, from this directory:

```console
$ cargo run --bin wsl-client
```

Expected: the WSL2 side prints the echoed message it got back from Windows.
That confirms a live, working byte-stream connection crossed the VM boundary
with no virtual network involved. Confirmed on
`6.18.33.2-microsoft-standard-WSL2` against a Windows host:

```console
$ cargo run --bin wsl-client
connecting to host over AF_VSOCK, port 0x00005A17...
sent: hello from wsl2
received: windows-host-echo: hello from wsl2
```

## If it doesn't connect

Hyper-V Sockets fail silently (connection just times out) rather than with a
clear error when the two ends disagree on GUIDs, or when the `ServiceId`
isn't registered. In order of likelihood:

1. The listener is bound to `HV_GUID_CHILDREN` (no VM ID argument given).
   Confirmed by reproduction: registering the `ServiceId` alone did not fix a
   `Os { code: 110, kind: TimedOut }` from `wsl-client`, with the listener
   never printing `client connected` — consistent with
   [microsoft/WSL#5751](https://github.com/microsoft/WSL/issues/5751). Pass
   the real VM ID from `hcsdiag list` instead.
2. The one-time registry setup hasn't been done. This also produced the exact
   same silent timeout in isolation before the `ServiceId` was registered, so
   it's not distinguishable from (1) by symptom alone — check both.
3. The `hcsdiag list` VM ID is stale (WSL2's utility VM restarted since you
   read it — see "One-time setup" above). Re-run `hcsdiag list` and restart
   the listener with the fresh value.
4. The Windows Defender Firewall or an AV product is blocking Hyper-V socket
   traffic (rare, but some endpoint security products intercept `AF_HYPERV`).
5. The WSL2 kernel lacks `hv_sock` support. Check with
   `zgrep HYPERV_VSOCKETS /proc/config.gz` — it needs to report `y` or `m`
   (confirmed `y` on the kernel this spike was written against:
   `6.18.33.2-microsoft-standard-WSL2`).
6. The `ServiceId` GUID byte layout is wrong after all. The value in
   `windows_listener.rs` was cross-checked against a public copy of
   `hvsocket.h` and the binary cross-compiles and links cleanly, but neither
   proves the bytes are right at runtime — only running it does.

Already hit and fixed once: `socket()` returning `WSAEPROTONOSUPPORT`
(`Os { code: -2147014855, .. }`, decodes to `HRESULT_FROM_WIN32(10041)`).
Cross-compiling doesn't catch this because `0` ("family/type default") is a
perfectly valid *argument*, it's just semantically wrong for `AF_HYPERV` —
Hyper-V's provider never registers a default protocol. Per Microsoft's own
sample, the protocol argument must be `HV_PROTOCOL_RAW` (`1`) on the Windows
side (the Linux `AF_VSOCK` side does keep using plain `0`, since that
asymmetry is part of the documented API).

## Non-goals

- No authentication, no framing beyond a bare byte echo, no encryption.
- No attempt to reuse Factorseal's actual vault wire protocol.
- No packaging, no CI wiring, no product code changes.

A real integration would still need: an application-layer token exchanged
out-of-band (e.g. a file under the Windows user's profile, readable from WSL2
via the 9P-backed `/mnt/c` mount) to substitute for the peer-identity checks
Hyper-V Sockets don't provide, and its own threat-model writeup alongside
`security/personal-sync-wire.md`. None of that is in scope here — this spike
only proves or disproves the transport.

## Open problem this spike surfaced

The `HV_GUID_CHILDREN` wildcard not working for WSL2 guests
([microsoft/WSL#5751](https://github.com/microsoft/WSL/issues/5751)) is more
than a spike inconvenience — it changes the shape of any real integration.
"Bind once with a wildcard VmId, accept from any WSL2 distro" is not
available; the host side would instead need to resolve the *current* WSL2
utility VM ID (via `hcsdiag list` or its underlying HCS API) and rebind every
time that VM restarts, and `hcsdiag` itself requires Administrator. A
production Factorseal Windows service would either need to run with enough
privilege to do that resolution itself, or shell out to something that can —
neither is free, and it's a meaningfully worse operational story than "listen
once, accept from any child" that the earlier design discussion assumed. This
is worth resolving (find the underlying HCS API call and its actual privilege
requirement, distinct from the `hcsdiag` CLI's) before committing to Hyper-V
Sockets as the transport in a real design, not just in this spike.

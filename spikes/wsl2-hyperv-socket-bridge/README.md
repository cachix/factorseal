# Spike: WSL2 to Windows host IPC over Hyper-V Sockets

## Status

Throwaway validation code. Nothing here is wired into `factorseal`, and none
of it should be imported by product crates. It exists to answer one narrow
question before any real design work starts:

> Can a process inside a WSL2 distro open a byte-stream connection to a
> listener on its Windows host without a virtual network, a TCP port, or a
> kernel module the user has to install by hand?

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
  accepts one connection from any child partition, echoes back whatever it
  reads with a fixed prefix, then exits. Windows-only; compiles to a no-op on
  other targets.
- `src/bin/wsl_client.rs` — connects from inside WSL2 over `AF_VSOCK` to
  `VMADDR_CID_HOST`, sends one message, prints the echo, then exits.
  Linux-only; compiles to a no-op on other targets.

Both sides agree on a single `u32` port (`PORT` constant, currently
`0x0000_5A17`, duplicated in both files since a shared crate isn't worth it
for one constant). The Windows side turns that port into a Hyper-V Sockets
`ServiceId` GUID using Microsoft's well-known port-compatibility template
(`xxxxxxxx-FACB-11E6-BD58-64006A7986D3`); the Linux `AF_VSOCK` transport does
that same translation internally, so the Linux side just uses the port
directly.

This crate deliberately sits outside the main Cargo workspace (own
`[workspace]` table, not listed in the root `Cargo.toml` members) so it can't
affect `factorseal`'s build, lints, or CI, and so nobody mistakes it for
product code.

## How to run it

**On the Windows host** (needs Rust 1.91+; matches `docs/development.md`):

```powershell
cargo run --bin windows-listener
```

It prints a line when it starts listening, then blocks until a client
connects.

**Inside WSL2**, from this directory:

```console
$ cargo run --bin wsl-client
```

Expected: the WSL2 side prints the echoed message it got back from Windows.
That confirms a live, working byte-stream connection crossed the VM boundary
with no virtual network involved.

## If it doesn't connect

Hyper-V Sockets fail silently (connection just times out) rather than with a
clear error when the two ends disagree on GUIDs. In order of likelihood:

1. The `ServiceId` GUID template byte layout is wrong. Verify the constant
   against the Windows SDK's `hvsocket.h` or Microsoft's own
   `GuestCommunicationSample`; this code was written from memory of that
   template and hasn't been checked against the header.
2. The Windows Defender Firewall or an AV product is blocking Hyper-V socket
   traffic (rare, but some endpoint security products intercept `AF_HYPERV`).
3. The WSL2 kernel lacks `hv_sock` support. Check with
   `zgrep HYPERV_VSOCKETS /proc/config.gz` — it needs to report `y` or `m`
   (confirmed `y` on the kernel this spike was written against:
   `6.18.33.2-microsoft-standard-WSL2`).

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

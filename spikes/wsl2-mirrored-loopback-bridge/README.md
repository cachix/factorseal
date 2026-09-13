# Spike: WSL2 to Windows host IPC over loopback TCP (mirrored networking)

## Status

**Confirmed working, on the first attempt, with no elevation anywhere.** This
is the follow-up to `spikes/wsl2-hyperv-socket-bridge`, built after that
spike settled its own open question the wrong way for a real design:
Hyper-V Sockets work, but the host side needs *standing* Administrator
privilege to resolve the WSL2 utility VM's ID on every restart, with no
lower-privilege path (`microsoft/WSL#5751`, corroborated by the
independently-maintained `wsld` project). That's an ongoing privilege cost a
same-host named pipe or Unix socket transport never had.

`wsl-client` connected to `windows-listener.exe` over genuine `127.0.0.1` and
completed a full round trip:

```console
$ cargo run --bin wsl-client
connecting to 127.0.0.1:51027...
sent: hello from wsl2 over mirrored loopback
received: host-echo: hello from wsl2 over mirrored loopback
```

No Windows Firewall prompt appeared, and neither binary needed elevation —
unlike the Hyper-V Sockets spike, which needed a registry write, a specific
non-wildcard VM ID, and (for any real integration) standing admin. Mirrored
networking's `127.0.0.1` symmetry claim holds up in practice, not just in
the docs.

## Why this question matters

Same underlying need as the other spike: Factorseal's Windows desktop app
does TPM/Windows Hello sealing that a WSL2 guest can never do itself, so a
WSL2 build can only be a thin client forwarding requests to the real Windows
service. The question here is narrower than last time:

> Can a WSL2 process reach a loopback TCP listener on its Windows host via
> genuine `127.0.0.1` symmetry, with neither side running elevated?

WSL2's default NAT networking mode does **not** give this out of the box:
`localhostForwarding` only covers the Windows-connects-to-WSL2 direction; a
WSL2 process reaching a listener bound to the Windows host's `127.0.0.1`
normally requires resolving the host's NAT gateway IP instead (parsing
`/etc/resolv.conf` or the route table) — a workaround, not real loopback.
Mirrored networking mode (`networkingMode=mirrored`, stable since 2024) is
supposed to remove that asymmetry by giving WSL2 the same network interfaces,
and the same `127.0.0.1`, as the Windows host. This spike checks that claim
directly rather than trusting the docs, the same way the Hyper-V Sockets
spike checked `HV_GUID_CHILDREN` rather than trusting that it would work for
WSL2.

The peer-identity caveat from the other spike is unchanged either way: plain
loopback TCP carries no more peer identity than Hyper-V Sockets turned out to
have, so the application-layer token this needs is the same work regardless
of which of the two transports wins. This spike is only about the transport.

## What's here

- `src/bin/windows_listener.rs` — binds `127.0.0.1:51027`, accepts one
  connection, echoes back whatever it reads with a fixed prefix, then exits.
- `src/bin/wsl_client.rs` — connects to `127.0.0.1:51027`, sends one message,
  prints the echo, then exits.

Both are plain `std::net::{TcpListener, TcpStream}` — no `unsafe`, no
platform-specific dependencies, no hand-transcribed constants from an SDK
header. That's the main structural advantage over the Hyper-V Sockets spike:
there's no FFI surface to get wrong, so if this works, it's simpler to trust
and simpler to build on. Either binary will actually run on any OS since
there's nothing platform-specific in the code; the names describe the
intended role (host listener vs. guest client), not a compile-time
restriction.

This crate deliberately sits outside the main Cargo workspace (own
`[workspace]` table, not listed in the root `Cargo.toml` members), same as
the other spike.

## One-time setup on the Windows host

Unlike the Hyper-V Sockets spike, **nothing here requires Administrator.**
Mirrored networking is a per-user setting in `.wslconfig`.

1. Create or edit `%UserProfile%\.wslconfig` (an ordinary user-writable
   file — no elevation) with:

   ```ini
   [wsl2]
   networkingMode=mirrored
   ```

2. Restart WSL2 from an ordinary (non-admin) terminal:

   ```powershell
   wsl --shutdown
   ```

   Then relaunch your distro. `.wslconfig` changes only take effect after a
   full WSL2 restart, same as the Hyper-V VM-ID caveat from the other spike —
   except here nothing about the restart itself needs a privileged step.

3. Sanity-check mirrored mode actually took effect before blaming the spike
   code for a failure: run `ip addr` inside WSL2 and compare against
   `ipconfig` on Windows. Under mirrored mode they should show the same IP
   addresses on the same-named adapters, not WSL2's own separate
   `172.x.x.x`-style NAT subnet.

## How to run it

**On the Windows host** (needs Rust 1.91+; matches `docs/development.md`):

```powershell
cargo run --bin windows-listener
```

**Inside WSL2**, from this directory:

```console
$ cargo run --bin wsl-client
```

Expected: `wsl-client` prints the echoed message back from the Windows host,
having reached it via literal `127.0.0.1` — no NAT gateway IP, no Hyper-V
GUID gymnastics.

## If it doesn't connect

1. Mirrored mode didn't actually take effect. Re-check with `ip addr` /
   `ipconfig` as above; a stale `wsl --shutdown` (some other WSL-attached
   process kept the VM alive) is the most likely cause.
2. Windows Defender Firewall prompts for the listener. This would itself be
   informative: genuine loopback traffic (`127.0.0.1`) is not supposed to
   cross the Windows Filtering Platform's normal inbound rules regardless of
   interface mirroring, so a prompt here would mean mirrored mode is doing
   something less loopback-like than advertised — worth reporting back
   rather than just clicking through it.
3. Something else entirely is bound to port `51027` on one side. Pick a
   different `PORT` in both files if so; there's nothing meaningful about
   this specific number.

## Non-goals

- No authentication, no framing beyond a bare byte echo, no encryption —
  same scope limit as the other spike, for the same reason (the real
  application-layer token work is identical regardless of which transport
  wins).
- No attempt to reuse Factorseal's actual vault wire protocol.
- No packaging, no CI wiring, no product code changes.

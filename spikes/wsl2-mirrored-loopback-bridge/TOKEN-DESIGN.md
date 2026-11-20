# Application-layer token design for the WSL2 loopback bridge

## Scope

This designs the authentication layer that `README.md`'s "Non-goals" section
called out as missing: loopback TCP over mirrored networking has zero peer
identity, so something has to stand in for the `SO_PEERCRED`/impersonation
checks the native Linux/macOS/Windows transports rely on
(`docs/architecture.md`, "Linux uses a private Unix socket, `SO_PEERCRED`...
/ Windows uses a same-user named pipe, client impersonation, SID and PID").

This is a design, not a product change — nothing here is wired into
`factorseal`. The one part of it that's an empirical claim rather than a
policy choice (can a WSL2 process actually read a token file written by a
Windows-native process under that user's `%LOCALAPPDATA%`, with no extra
setup) is validated by extending the existing spike; see the last section.

## Threat model

Working through this carefully surfaced something more serious than earlier
discussion assumed. There are three attacker classes to consider, and
they're not equally well known going in:

1. **Another process in the same WSL2 distro as the legitimate client.**
   Not mitigated by this token, and can't be — if the distro is compromised
   or shared, anything running in it can read the same token file the
   legitimate client reads. This is inherent to the "thin client in a distro
   you trust" model, already noted in the Hyper-V spike's README, and out of
   scope here.

2. **Another process on the Windows host, running as the *same* Windows
   user.** Also not a new weakness: every other same-host Factorseal
   transport (the named pipe, the Unix sockets) only ever guaranteed
   "same OS user," never "only Factorseal's own client." This token doesn't
   need to close that gap because nothing else in the product does either.

3. **Another process on the Windows host running as a *different* Windows
   user, or a background service account.** This is the one that changes
   the picture. Named pipes carry a per-object ACL restricting connections
   to a specific SID — that's the actual mechanism behind "same-user named
   pipe" in the architecture doc. A raw TCP listener on `127.0.0.1` has no
   equivalent object-level access control: on Windows, loopback TCP's port
   namespace is machine-wide, not per-session. If a second person is logged
   in concurrently (fast user switching, RDP) or a service account is
   running under a different SID, their processes — and *their* WSL2
   instances, since mirrored networking gives every session the same host
   loopback interface — can all reach `127.0.0.1:51027` exactly as easily as
   the legitimate user's client can. Switching from a named pipe to loopback
   TCP quietly gave up the "same user" guarantee entirely, not just the
   "same VM" guarantee the Hyper-V Sockets spike was built to check. The
   token is now the *only* thing enforcing "same user," not a
   defense-in-depth layer on top of one.

## Known v1 limitation this threat model surfaces: single active user

Because the loopback port namespace is machine-wide, only one Windows
session's Factorseal service can bind a fixed port like `51027` at a time.
On a shared multi-user machine, whichever session's service starts first
wins the port; a second concurrent user's service would fail to bind
(`EADDRINUSE`). Hyper-V Sockets didn't have this problem — each WSL2
instance gets its own VM ID, so the address space naturally partitions per
session. This is a real cost of the transport switch, not a token-design
detail, and it's being accepted as a v1 limitation rather than solved here:
per-session port derivation (e.g. from the session ID) would fix it but is
out of scope for this design. Worth flagging explicitly rather than
discovering it later — Factorseal's primary target (a personal desktop
vault) likely makes this an acceptable trade, but it should be a deliberate
acceptance, not an oversight.

## Token properties

- **Generation:** 32 bytes from the OS CSPRNG (`getrandom`), hex-encoded for
  safe storage in a text file.
- **Lifetime:** scoped to one run of the Windows service — a fresh token is
  generated every time the service starts, which invalidates any old token
  automatically. This mirrors the "identification-only tokens" already used
  for Windows named-pipe clients (`docs/architecture.md:98`) rather than
  inventing new mechanics. Rotating independently of service restarts (e.g.
  hourly, to bound exposure on a long-running service) is deliberately not
  in v1 — it adds coordination complexity (existing connections holding the
  old token, when to invalidate it) for a benefit that's marginal as long as
  the token file itself is properly ACL'd; revisit only if that assumption
  turns out to be wrong in practice.
- **Storage:** a file under the Windows user's own profile (e.g.
  `%LOCALAPPDATA%\Factorseal\wsl-bridge-token`). The actual access control is
  whatever NTFS ACL already applies to `%LOCALAPPDATA%` (owner + SYSTEM +
  Administrators, by default) — nothing here adds a stronger guarantee than
  that ACL provides, it just rides on it.
- **Read path from WSL2:** the drvfs-backed `/mnt/c/Users/<user>/AppData/Local/...`
  mount. The security-relevant assumption is that a WSL2 instance accesses
  `/mnt/c` using the identity of whichever Windows user's session launched
  that instance — i.e. User B's WSL2 distro can't browse into User A's
  `%LOCALAPPDATA%` any more than User B's own Windows Explorer could. This
  is standard NTFS ACL enforcement, not something specific to WSL2, but it's
  the load-bearing assumption for this whole design and is worth stating
  plainly rather than leaving implicit.

## Protocol placement

The token is the first thing sent on the connection, before any byte of the
real vault protocol:

1. Client connects, sends the 32-byte token (as raw bytes, not hex, once
   past the file-storage boundary — hex encoding is only for safe storage in
   a text file, not for the wire).
2. Server reads exactly 32 bytes and compares against the expected token in
   constant time (a length-independent, secret-independent-branch
   comparison — both sides always exchange exactly 32 bytes, so there's no
   length side-channel to worry about either).
3. On mismatch: close the connection immediately, no response of any kind.
   Do not distinguish "wrong token" from "malformed input" from any other
   failure — an unauthenticated peer gets no protocol oracle to probe.
4. On match: proceed to the real protocol.

## Explicitly out of scope

- A compromised WSL2 distro belonging to the *legitimate* user (attacker
  class 1 above) — this token can't fix a trust boundary that was never
  there to begin with.
- Multi-user concurrent access to the same bridge port (see "Known v1
  limitation" above) — accepted, not solved, here.
- Token rotation independent of service restart — deferred until proven
  necessary.
- Anything about the real vault wire protocol itself — this only covers the
  authentication gate in front of it.

## Validated by extending the spike

The generation/lifetime/protocol-placement decisions above are policy
choices, not things that need runtime proof. The one genuinely uncertain
claim — that a WSL2 process can read a token file written by a native
Windows process under `%LOCALAPPDATA%`, transparently, with no extra
configuration on either side — is exactly the kind of thing this whole
investigation has insisted on checking empirically rather than trusting.
`windows_listener.rs` and `wsl_client.rs` were extended to generate, write,
read, and check a real token over the existing loopback connection; see the
updated "How to run it" section in `README.md` for the result.

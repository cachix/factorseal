# FactorSeal Desktop

The GPUI-based graphical vault host. It can initialize a vault, unlock it with
one configured factor group, host FactorSeal's authenticated native service,
and seal it from the window or tray. Password input uses zeroizing masked fields. A dedicated CLI worker receives
factors over private inherited pipes, performs native biometric ceremonies,
and owns the keys and database. Desktop requests go through the same
authenticated native IPC as other clients. The worker drops the unlock password
before serving and exits when Desktop closes its lifeline or dies.

Desktop and `factorseal agent` are two front ends for the same vault host. Run
one at a time. If an agent already owns the endpoint, Desktop reports its live
lease without attempting to take it over. A second Desktop invocation signals
the first instance to activate instead of starting another host.

On Linux, the installed Desktop package also provides the session-bus
activation record for `org.freedesktop.secrets`. A keyring request while sealed
starts Desktop, or activates its existing window, so the user can authenticate.
Once unsealed, the normal Secret Service adapter claims the bus name and handles
the queued request. The requesting application's D-Bus timeout bounds the time
available to finish authentication.

On Linux, theme probes run as short-lived child processes so GTK and Qt never
initialize their global toolkit state inside GPUI. Desktop follows the native
light/dark preference and system typography, then applies FactorSeal's Ink
tokens so the product remains recognizable across desktop environments. The
XDG settings portal and relevant theme files are watched for changes.

Native integration is isolated in `src/theming.rs`, brand tokens in
`src/branding.rs`, and the window and tray in `src/app.rs`.

The interface follows the [brand guide](../BRAND.md): a single-color chip mark,
Ink and Paper surfaces, native sans-serif typography, labeled fields, and
explicit sealed/unsealed states. The vault browser uses the available window
space; setup and unlock forms stay compact and scroll when the window is short.
The mark stays monochrome in error states, while green identifies an unsealed
vault and red identifies errors. Small marks use the optical artwork, shared
with the generated tray icons.

## Run

From the repository root:

```console
devenv shell cargo build -p factorseal --features cli,vault,hardware
devenv shell cargo run -p factorseal-desktop
```

Install both binaries together, or set `FACTORSEAL_CLI_EXECUTABLE` to the absolute
CLI path. The Nix Desktop package supplies this dependency automatically.

Set `FACTORSEAL_TIMINGS=1` when launching Desktop to log unlock timings to
stderr, including worker setup, executable authentication, permission writes,
service readiness, and inventory loading. Desktop passes this setting to its
CLI worker. Logs contain phase names, durations, and success/error outcomes.
The worker-ready wait includes the worker's startup phases, and host-authorization
timing includes its grant read and any batched write; these nested timings are not additive.
Readiness is reported after the native listener and lifecycle hooks are installed.
The first status probe includes caller authentication and request handling; request
lock waits are nested within handling. Linux also logs listener setup, expiry
sweeps, and Secret Service name claiming, authorization, and index loading.
SecretSpec discovery leaves an unchanged, correctly protected claim in place.
Its timings separate directory preparation and comparison from temporary-file
writing, disk flush, and rename; the latter phases appear only when replacing a claim.
Host executable identification overlaps TPM/password unsealing; only
`wait_host_identities` adds time after unsealing if identification is still running.
Password timings separate scratch-memory allocation, Argon2, and secure cleanup.
The initial unlocked view waits for inventory, then loads permissions separately;
`permissions_ready` records when that follow-up has reached the UI.

The installed CLI launches the separately packaged application with:

```console
factorseal desktop
factorseal desktop --background
```

Linux currently offers password initialization because the TPM backend does
not implement biometric policy. macOS and Windows expose biometric-only,
password-and-biometric, and password-or-biometric policies in addition to
password-only setup.

## Import and export

The global Import and Export views support four formats:

- `.factorseal`: a versioned, lossless archive encrypted with a separate
  passphrase using Argon2id and AES-256-GCM. It includes durable entries and
  their expiry deadlines, but intentionally excludes provider caches,
  application authorizations, audit history, and device keys. Restore writes
  every entry through the live agent so it is protected by the destination
  device's hardware-backed vault keys.
- Bitwarden JSON, 1Password CSV, and KeePass CSV: plaintext migration formats
  for Personal secrets only. Login names, passwords, URLs, TOTP seeds, notes,
  folders/tags where supported, and custom fields are mapped into FactorSeal's
  versioned personal-secret record. Legacy FactorSeal name/value records remain
  readable and exportable.

Imports keep existing entries by default; the user can explicitly choose to
replace matching names or addresses. Password-manager exports require an
explicit plaintext warning acknowledgement and are written with user-only file
permissions before writing on Unix and Windows. New vault passwords and archive
passphrases share the library strength policy; legacy unlock/decrypt remains
compatible. Secret fields are always masked and do not support copying or undo.

Automatic selection uses the detected desktop environment. It prefers Qt on a
Qt desktop and GTK otherwise. The choice can be overridden for development:

```console
NATIVE_THEME_BACKEND=qt devenv shell cargo run -p factorseal-desktop
NATIVE_THEME_BACKEND=gtk devenv shell cargo run -p factorseal-desktop
```

Resolve the native theme without opening the GPUI window or tray:

```console
devenv shell cargo run -p factorseal-desktop -- --theme-probe-only
```

## Crash reports and logs

Settings → Diagnostics → Export diagnostics saves a private JSON bundle for
review and sharing. The CLI provides the same export even when Desktop cannot
open or the vault is sealed:

```console
factorseal diagnostics
factorseal diagnostics --output factorseal-diagnostics.json
```

The first command prints the storage directory. Reports live in the platform's
local Factorseal application-data directory under `diagnostics`; set
`FACTORSEAL_DIAGNOSTICS_DIR` to use another location. Automatic submission requires
a configured Sentry DSN, as described below. The bug button immediately before
“Your secrets stay here” opens a form for describing what happened, what was
expected, and steps to reproduce. A nonempty description (up to 4,000 characters)
is required. Send report submits the description with the current Desktop
diagnostic log without requiring a crash; Cancel sends nothing. It reports successful delivery only after Sentry
acknowledges receipt; offline or delayed submissions remain queued for retry.

Desktop, CLI, and vault workers record their version, OS, architecture, PID,
startup time, lifecycle operations, and outcomes. Unlock and storage timings
are kept in a 128-event memory buffer and flushed with lifecycle events, normal
exit, or a Rust panic. This works without enabling `FACTORSEAL_TIMINGS` and avoids
disk writes on routine timing events. Supervised worker exits include the child
PID, exit code, and Unix signal, so the worker's report can be correlated with
Desktop's log.

Rust panics on any thread create a separate report with the recent log, source
location, and a forced backtrace. Up to 20 recent session snapshots and 20 panic/worker-failure/manual-issue
reports are retained independently, with a 256 KiB limit per file. New files and
exports use owner-only permissions on Unix and Windows. Retention runs when a
report is written. Deleting the diagnostics directory clears local history.

Automatic diagnostics exclude secret values, vault contents, arguments, environment variables,
raw error strings, thread names, and panic payloads. They do not collect memory
dumps or redirect stderr. Backtraces may contain build-time source paths, so
review the export before sharing it. Release builds retain line tables; packages
must retain debug symbols for useful source locations. Descriptions entered in
the issue form are sent as written and retained with queued reports for retries;
do not include passwords or secret values. Drafts stay in memory until submitted.

Native faults, aborts, out-of-memory termination, forced kills, and power loss
cannot run the Rust panic hook. They leave the last persisted session snapshot;
Desktop also records an abnormal worker exit when it can observe one. A snapshot
marked `running` can belong to a live process or one that exited without cleanup
and is not, by itself, proof of a crash. There is no native crash stack or dump
capture. Reporting is best effort if storage becomes unavailable.

### Automatic Sentry submission

Only the primary Desktop process performs HTTP delivery. The CLI, agent, and
vault worker do not link the Sentry/HTTP delivery code. Desktop submits its own
panic and abnormal-worker-exit reports, plus panic reports saved by Desktop's
CLI worker. The footer bug button also submits an explicit snapshot of the
current Desktop log and the user's description as a “User-reported issue”,
without a crash exception. The description appears in Sentry's additional data
as `issue_description` and is excluded from unrelated crash events.
Unrequested normal session logs and unrelated CLI/agent reports are excluded.

For development, set the runtime configuration before starting Desktop:

```console
SENTRY_DSN='<your-project-dsn>' SENTRY_ENVIRONMENT=development devenv shell cargo run -p factorseal-desktop
```

Release builds embed FactorSeal's public project DSN from `sentry-dsn.txt` by
default. This covers Cargo release builds on every desktop platform and the Nix
Desktop package. Debug builds stay local unless explicitly configured.
Release builders can override the embedded DSN and environment:

```console
FACTORSEAL_SENTRY_DSN='<your-project-dsn>' FACTORSEAL_SENTRY_ENVIRONMENT=production devenv shell cargo build --release -p factorseal-desktop
```

The Nix Desktop derivation accepts `sentryDsn` and `sentryEnvironment` override
arguments for the same purpose. A runtime `SENTRY_DSN` overrides the embedded
value; setting it to an empty string disables submission. An empty build-time
`FACTORSEAL_SENTRY_DSN` (or Nix `sentryDsn = ""`) also disables the default.
Runtime `SENTRY_ENVIRONMENT` overrides
`FACTORSEAL_SENTRY_ENVIRONMENT`; otherwise it defaults to `development` for debug
builds and `production` for release builds. Environment labels support letters,
numbers, hyphens, and underscores, up to 64 characters. Invalid configuration
leaves local reporting available and produces a generic startup error. No
Sentry authentication token belongs in the application. The public project DSN
is intended to be embedded in distributed applications; users of release builds
should not need to configure it themselves.

With a valid HTTPS DSN, automatic submission is on by default. Settings →
Diagnostics → Automatically send crash reports can pause and resume delivery.
Turning it off prevents subsequent automatic crash requests; an already-running
request may finish. Explicit submissions through the bug button still send and
retry while this switch is off. Local recording continues, and pending crash
reports can be submitted when automatic submission is enabled again.
Configuring Sentry for the first time (or changing
projects) sets a timestamp boundary: older local-only history is not uploaded.

The background uploader checks for incidents every five seconds. A Desktop
panic that terminates the process is submitted on the next launch. Failed
requests remain pending across restarts, subject to the existing 20-incident
retention limit. A private `sentry-delivery.json` file records the target,
initial timestamp boundary, accepted event IDs, and the next retry time.
Delivery is acknowledged only for successful HTTP responses. Requests time out
after ten seconds, redirects are rejected, and failures back off for at least
60 seconds while respecting Sentry quota delays and numeric Retry-After values.
Retries keep the same Sentry event ID, including if an acknowledgement could not
be saved locally. The uploader never waits inside the panic hook or key-owner
shutdown path.

To check a real Sentry project, explicitly run the ignored integration test:

```console
SENTRY_DSN='<your-project-dsn>' devenv shell cargo test -p factorseal-desktop live_sentry_submission -- --ignored --nocapture
```

This sends two events under `integration-test`: a manual issue while automatic
reporting is off, and a controlled panic recovered by a fresh process. It uses a
temporary diagnostics directory and requires an HTTP acknowledgement for each
event. Normal test runs skip it. Confirm the events and breadcrumbs in Sentry's
project view to verify processing after ingestion.

Sentry events contain version-based release metadata, component/OS/architecture
tags, parsed Rust exception frames, and recent operation logs as breadcrumbs.
Absolute source paths are removed from submitted frames. Hostnames, user
identity, environment variables, command arguments, raw panic payloads, and raw
log/error strings are not captured. Sentry's default integrations are disabled;
its SDK protocol types construct the envelopes, and an acknowledged HTTP
transport handles durable delivery. The local report remains available after a
successful submission. Native crash-stack capture is still outside this path.

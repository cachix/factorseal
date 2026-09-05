# FactorSeal Desktop

The GPUI-based graphical vault host. It can initialize a vault, unlock it with
one configured factor group, host FactorSeal's authenticated native service,
and seal it from the window or tray. Password input and native biometric
ceremonies remain inside the Desktop process; secrets are still served through
the same caller-authenticated socket, pipe, and platform keyring adapters as
the headless agent.

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
devenv shell cargo run -p factorseal-desktop
```

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
permissions on Unix systems.

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

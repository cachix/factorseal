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
initialize their global toolkit state inside GPUI. The parent converts the
result through `native-theme-gpui`, watches the XDG settings portal and relevant
theme files, and reapplies the theme when they change.

The theming implementation is isolated in `src/theming.rs`; the window and tray
remain in `src/app.rs`.

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

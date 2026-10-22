# GPUI Community Edition integration

Desktop uses the crates.io releases `gpui-ce` 0.3.0, `gpui_ce_platform` 0.3.0,
and `gpui-tray` 0.3.0. The dependency aliases preserve the application's `gpui`
and `gpui_platform` imports. Core, platform, components, assets, and tray resolve
one GPUI CE package. The previous core and oo7 Git patches are removed.

## Component compatibility

Components and assets are pinned to Git revision
`540da44d442e7e5be870e44a02858d95fd74b153` on `domenkozar/gpui-kit`, the head of
[upstream compatibility PR #6](https://github.com/gpui-ce/gpui-component/pull/6).
The port is based on current upstream main
`c08206932417f863062d2ab70cc2854c6ca04238`. No local component sources are needed.
Nix records the Git source hash in `nix/cargo-output-hashes.nix`.

The PR updates dependency requirements and adapts the inspector, content masks,
painting, shaping, activation, and profiling APIs. It removes the duplicate
`StyledExt::refine_style` method in favor of GPUI's `Styled` method. The editor's
internal wrapper preserves boundary, atomic-element, and indentation behavior
while measuring through the 0.3 shaper, including fallback fonts. Rich text uses
backend visual lines and cluster geometry. Custom text renderers retain their
own layout node so automatic inline flow cannot bypass their measurement.

The PR is a draft. The non-WebView upstream workspace type-checks on Linux,
including Story and examples. The initial full upstream run reported 1,210 Base tests passed and 17 failed;
Component reported 554 passed, 12 failed, and one ignored. The
remaining failures include layout/scrolling, text wrapping/reveal, measurement
caches, and test-backend behavior. They have not all been classified as
fixture-only and must be resolved before upstream merge. The two real-Parley
wrapping and caret regression tests pass. WebView checking requires WebKitGTK.

A follow-up migrates native-menu icon loading to GPUI 0.3's `AssetRegistry`,
fixing macOS and Windows compilation after `App::asset_source` was removed.
All seven native-menu tests pass on Linux, including icon resolution tests
previously restricted to macOS and Windows. Native CI must verify the backends.

After the PR is merged, prefer the upstream merge commit or a compatible
published component release. Update the Cargo revision and Nix hash together.

## Desktop adaptations

Protected inputs still shape only bullets when masked. Visible multiline
fields use one `ShapedText` layout for hard breaks and soft wrapping, including
selection bounds and caret hit testing. Single-line inputs use GPUI's caret API
directly. The font fallback check uses the public font-family list, and window
restoration uses `Window::activate`.

Current upstream Root mounts dialog and notification layers automatically.
Desktop no longer mounts those layers itself. Removed tile-specific theme fields
are also removed from the application theme definition.

GPUI's stable Linux platform uses oo7 0.6 with zbus 5. FactorSeal's own D-Bus
interfaces, the ashpd patch, and gpui-tray use zbus 6. Desktop does not call
GPUI's credential-storage methods. Moving oo7 to zbus 6 is a separate upstream
migration and no longer requires a GPUI fork here. The component asset HTTP
update removes rustls-pemfile and its obsolete maintenance exception.

## Validation

The final Git-pinned checkout passed the Linux Desktop tests: 200 passed, with
one live Sentry test ignored. Regression coverage uses Parley with bundled IBM
Plex to check Unicode/multiline caret hit testing and masked input. Atomic
inline-element wrapping is tested in the upstream PR.

Workspace Clippy with all targets/features and warnings denied passes, as do
formatting, the dependency audit (six explicit maintenance exceptions), eight
dependency-policy tests, and Desktop Nix derivation evaluation. The Nix source
hash was obtained by fetching the published Git commit.

An isolated nested Wayland session rendered the setup screen and exited
normally on window close with an empty runtime log. It used a temporary root
and isolated settings with `--no-tray --no-secret-service`; no vault was created
or unlocked. The local screenshot is
`/tmp/factorseal-components-git-smoke/desktop.png`.

Native macOS/Windows checks, a full Nix package build, tray lifecycle
interaction, and the 29 remaining upstream regressions require further
validation. Upstream CI also has failing jobs that need triage. The draft PR
records those limits explicitly.

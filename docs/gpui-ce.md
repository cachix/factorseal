# GPUI Community Edition integration

FactorSeal uses GPUI CE for its core, native platform, components, assets, and
tray. The dependency aliases preserve existing `gpui`, `gpui_component`,
`gpui_component_assets`, and `gpui_platform` imports.

## Pinned sources

| Dependency | Revision |
| --- | --- |
| [GPUI CE](https://github.com/gpui-ce/gpui-ce) | `05d89e953701a89fedac9b17b3042154bdf74afe` |
| [CE component compatibility branch](https://github.com/domenkozar/gpui-kit/tree/factorseal/gpui-ce-05d89e95) | `c7440f24e3c392beefe759aeb7989bd4ea4ffd4e` |
| [gpui-tray 0.1.1](https://github.com/domenkozar/gpui-tray) | `db57d965a7187563644c5028bb1a17d36486b919` |

The component branch starts at the CE-maintained
[gpui-component fork](https://github.com/gpui-ce/gpui-component), revision
`f7fbbbb2b34dc131414ddeafee904102631b92ea`. Its compatibility commit removes the
obsolete `runtime_shaders` feature and renames `Deferred::with_priority` calls
to `Deferred::priority`. It can be replaced by an upstream revision containing
those changes once that revision has been validated against the pinned core.

The desktop selects gpui-tray's `gpui-ce,menu-state` features and disables its
default Zed GPUI backend. Workspace patches for crates.io `gpui-ce`,
`gpui_ce_platform`, and `gpui_ce_macros` keep transitive dependencies on the same
Git revision. Cargo package identity matters: patching `gpui` to a package
named `gpui-ce` does not make Longbridge's original component packages use CE.

CE includes `Window::set_visible`, so the previous Zed visibility fork is no
longer needed. The existing tray and window lifecycle logic remains in place.

## Application adaptations

- Convert native and brand RGB colors with `gpui::rgb_to_hsla`.
- Import `gpui::ColorExt` for alpha multiplication with `opacity`.
- Use the CE color type's `lightness` field in the decorative unlock animation.
- Forward text-style letter spacing to secret-field `TextRun` values.

The new SVG dependency chain no longer contains `rustybuzz`, so its obsolete
maintenance exception is removed. Nix Cargo output hashes cover the CE core,
component fork, tray, and shader generator Git sources.

## Validation

Validation on Linux:

- `cargo build --locked -p factorseal-desktop`: passed.
- `cargo test --locked -p factorseal-desktop`: 56 passed, one live Sentry test
  ignored.
- `cargo clippy --locked -p factorseal-desktop --all-targets --all-features -- -D warnings`:
  passed.
- Formatting, the dependency-policy check with cargo-audit 0.22.2, and all seven
  dependency-policy tests passed.
- `cargo tree` confirms the core, components, assets, tray, and platform resolve
  the same CE revision.
- Nix evaluation and the new core/component/shader Git dependency derivations
  passed, including source hash verification. The full vendor download was
  stopped; a full Nix desktop build has not been run.
- An isolated Niri/Wayland instance with an uninitialized temporary vault and
  Secret Service hosting disabled passed background startup, tray activation,
  menu open/hide, close-to-tray, five additional hide/show cycles, and tray quit.
  The setup screen rendered correctly before and after restoration; both
  screenshots were byte-identical. The process exited successfully and its
  tray service disappeared. No vault initialization or unlock was performed.

The Windows desktop and test targets passed `cargo xwin check` using LLVM 21.1.8.
The local cross environment used unwrapped Clang, `llvm-lib`, and a resource
compiler wrapper that adds the crate root to manifest lookup paths. CE's
`GPUI_RENDER_ALLOW_MISSING_DXBC=1` was set for this check-only build; Windows
release builds must run on Windows to produce the required DXBC shaders. The
check reported an existing dead-code warning for the non-Linux permission
helpers `approve_permissions` and `deny_permission`.

Windows runtime and macOS require native CI validation.

//! Window activation and compositor-specific fallbacks.
use gpui::{AnyWindowHandle, App, Window};

#[cfg(target_os = "linux")]
use super::{DesktopWindow, niri};

/// Present an existing desktop window. Call after action dispatch releases it.
pub(super) fn desktop(handle: AnyWindowHandle, cx: &mut App) -> anyhow::Result<()> {
    handle.update(cx, |_, window, cx| {
        #[cfg(not(target_os = "linux"))]
        let _ = cx;
        #[cfg(target_os = "linux")]
        if cx.global::<DesktopWindow>().visible
            && !window.is_window_active()
            && std::env::var_os("NIRI_SOCKET").is_some()
        {
            focus_niri(handle, cx);
            return;
        }
        let remap_unfocused =
            cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some();
        show(window, remap_unfocused);
    })
}

/// Present an ordinary window, optionally remapping it to recover focus.
/// Layer-shell approval surfaces must skip this fallback.
pub(super) fn show(window: &mut Window, remap_unfocused: bool) {
    if remap_unfocused && !window.is_window_active() {
        window.set_visible(false);
    }
    window.set_visible(true);
    window.activate_window();
}

#[cfg(target_os = "linux")]
fn focus_niri(handle: AnyWindowHandle, cx: &mut App) {
    cx.spawn(async move |cx| {
        if !smol::unblock(niri::focus_desktop).await {
            cx.update(|cx| {
                let desktop = cx.global::<DesktopWindow>();
                // Ignore a failed request if its window was hidden or replaced.
                if desktop.visible && desktop.handle == Some(handle) {
                    let _ = handle.update(cx, |_, window, _| show(window, true));
                }
            });
        }
    })
    .detach();
}

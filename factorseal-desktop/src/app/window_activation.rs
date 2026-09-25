//! Window activation and compositor-specific fallbacks.
use gpui::{AnyWindowHandle, App, Window};

#[cfg(target_os = "linux")]
use super::{DesktopWindow, niri};

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub(super) fn configure_desktop(window: &Window) {
    use objc2_app_kit::{NSView, NSWindowCollectionBehavior};
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let Ok(handle) = HasWindowHandle::window_handle(window) else {
        return;
    };
    let RawWindowHandle::AppKit(handle) = handle.as_raw() else {
        return;
    };
    // SAFETY: GPUI lends a valid NSView for this window on the main thread.
    let view = unsafe { &*handle.ns_view.as_ptr().cast::<NSView>() };
    if let Some(window) = view.window() {
        // Bring the window to the current Space when activated.
        window.setCollectionBehavior(
            window.collectionBehavior() | NSWindowCollectionBehavior::MoveToActiveSpace,
        );
    }
}

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

/// Flag a window in the taskbar when it could not take the foreground.
pub(super) fn request_attention(window: &Window) {
    #[cfg(target_os = "windows")]
    win32::flash_until_foreground(window);
    #[cfg(not(target_os = "windows"))]
    window.request_attention();
}

/// GPUI's `request_attention` skips windows that `GetActiveWindow` reports as
/// active. A newly shown window is always its own thread's active window, even
/// when another app keeps the foreground, so on Windows it never flashes.
#[cfg(target_os = "windows")]
mod win32 {
    #![allow(unsafe_code)]
    use gpui::Window;
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        FLASHW_ALL, FLASHW_TIMERNOFG, FLASHWINFO, FlashWindowEx, GetForegroundWindow,
    };

    /// Flash the taskbar button until the window comes to the foreground.
    pub(super) fn flash_until_foreground(window: &Window) {
        // GPUI's inherent `Window::window_handle` returns its own handle type.
        let Ok(handle) = HasWindowHandle::window_handle(window) else {
            return;
        };
        let RawWindowHandle::Win32(handle) = handle.as_raw() else {
            return;
        };
        let hwnd = handle.hwnd.get() as HWND;
        // SAFETY: GetForegroundWindow takes no arguments and only reads state.
        if unsafe { GetForegroundWindow() } == hwnd {
            return;
        }
        let info = FLASHWINFO {
            cbSize: u32::try_from(std::mem::size_of::<FLASHWINFO>())
                .expect("FLASHWINFO is a few dozen bytes"),
            hwnd,
            dwFlags: FLASHW_ALL | FLASHW_TIMERNOFG,
            uCount: 0,
            dwTimeout: 0,
        };
        // SAFETY: `info` is a fully initialized FLASHWINFO for a live window
        // owned by this thread, and it outlives the call.
        let _ = unsafe { FlashWindowEx(&raw const info) };
    }
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

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

/// Flag a window in the taskbar when it could not take the foreground.
pub(super) fn request_attention(window: &Window) {
    #[cfg(target_os = "windows")]
    win32::flash_until_foreground(window);
    #[cfg(not(target_os = "windows"))]
    window.request_attention();
}

/// Flag a window that lost the foreground before the user interacted with it.
///
/// Windows can hand a new window the foreground for a moment and then give it
/// back to the app the user is typing in, so the check in
/// [`request_attention`] saw the window in front and did not flash. Other
/// platforms flag the window when it opens, so this only matters on Windows.
pub(super) fn deactivated_unseen(window: &Window) {
    #[cfg(target_os = "windows")]
    win32::flash_until_foreground(window);
    #[cfg(not(target_os = "windows"))]
    let _ = window;
}

/// Stop flagging a window that reached the foreground or is closing.
pub(super) fn attention_settled(window: &Window) {
    #[cfg(target_os = "windows")]
    win32::stop_owner_flash(window);
    #[cfg(not(target_os = "windows"))]
    let _ = window;
}

/// GPUI's `request_attention` skips windows that `GetActiveWindow` reports as
/// active. A newly shown window is always its own thread's active window, even
/// when another app keeps the foreground, so on Windows it never flashes.
///
/// GPUI also makes a dialog opened while Desktop's main window is active an
/// owned, modal window of it. An owned window has no taskbar button of its own,
/// so the owner's button is the one to flash.
#[cfg(target_os = "windows")]
mod win32 {
    #![allow(unsafe_code)]
    use gpui::Window;
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        FLASHW_ALL, FLASHW_STOP, FLASHW_TIMERNOFG, FLASHWINFO, FLASHWINFO_FLAGS, FlashWindowEx,
        GA_ROOTOWNER, GetAncestor, GetForegroundWindow,
    };

    fn hwnd(window: &Window) -> Option<HWND> {
        // GPUI's inherent `Window::window_handle` returns its own handle type.
        let handle = HasWindowHandle::window_handle(window).ok()?;
        let RawWindowHandle::Win32(handle) = handle.as_raw() else {
            return None;
        };
        Some(HWND(handle.hwnd.get() as *mut _))
    }

    /// The window whose taskbar button stands for `hwnd`.
    fn taskbar_window(hwnd: HWND) -> HWND {
        // SAFETY: GetAncestor only reads window relationships; a stale handle
        // yields a null result, which falls back to the window itself.
        let owner = unsafe { GetAncestor(hwnd, GA_ROOTOWNER) };
        if owner.is_invalid() { hwnd } else { owner }
    }

    fn flash(hwnd: HWND, flags: FLASHWINFO_FLAGS) {
        let info = FLASHWINFO {
            cbSize: u32::try_from(std::mem::size_of::<FLASHWINFO>())
                .expect("FLASHWINFO is a few dozen bytes"),
            hwnd,
            dwFlags: flags,
            uCount: 0,
            dwTimeout: 0,
        };
        // SAFETY: `info` is a fully initialized FLASHWINFO for a window of
        // this thread, and it outlives the call.
        let _ = unsafe { FlashWindowEx(&raw const info) };
    }

    /// Flash the taskbar button until the window comes to the foreground.
    pub(super) fn flash_until_foreground(window: &Window) {
        let Some(hwnd) = hwnd(window) else {
            return;
        };
        // SAFETY: GetForegroundWindow takes no arguments and only reads state.
        if unsafe { GetForegroundWindow() } == hwnd {
            return;
        }
        // For an owner, "until the foreground" would wait for a disabled
        // window; `stop_owner_flash` ends it when the dialog is in front.
        flash(taskbar_window(hwnd), FLASHW_ALL | FLASHW_TIMERNOFG);
    }

    /// Stop an owner's flash started for this window. A window's own flash
    /// already stops when it reaches the foreground.
    pub(super) fn stop_owner_flash(window: &Window) {
        let Some(hwnd) = hwnd(window) else {
            return;
        };
        let owner = taskbar_window(hwnd);
        if owner != hwnd {
            flash(owner, FLASHW_STOP);
        }
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

use std::{collections::HashMap, mem::size_of, sync::OnceLock};
use windows::{
    Win32::{
        Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM},
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Shell::{
                NIF_ICON, NIF_MESSAGE, NIF_SHOWTIP, NIF_STATE, NIF_TIP, NIM_ADD, NIM_DELETE,
                NIM_MODIFY, NIS_HIDDEN, NOTIFYICONDATAW, Shell_NotifyIconW,
            },
            WindowsAndMessaging::{
                AppendMenuW, CREATESTRUCTW, CreateIcon, CreatePopupMenu, CreateWindowExW,
                DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, GWLP_USERDATA,
                GetCursorPos, HICON, HMENU, MF_CHECKED, MF_GRAYED, MF_POPUP, MF_SEPARATOR,
                MF_STRING, RegisterClassW, RegisterWindowMessageW, SetForegroundWindow,
                SetWindowLongPtrW, TPM_LEFTALIGN, TPM_RETURNCMD, TPM_RIGHTBUTTON, TrackPopupMenu,
                WINDOW_EX_STYLE, WINDOW_STYLE, WM_APP, WM_CONTEXTMENU, WM_CREATE, WM_LBUTTONUP,
                WM_NCCREATE, WM_NCDESTROY, WM_RBUTTONUP, WNDCLASSW,
            },
        },
    },
    core::{PCWSTR, w},
};

use crate::{
    Error, Icon, Result,
    backend::BackendEvent,
    menu::{MenuItemId, MenuSnapshot, NativeMenuItem},
    tray::TraySnapshot,
};

const CALLBACK_MESSAGE: u32 = WM_APP + 0x471;
const ICON_ID: u32 = 1;

type MenuActions = HashMap<u32, (u64, MenuItemId)>;

pub(crate) struct WindowsTray {
    state: Box<WindowState>,
    closed: bool,
}

struct WindowState {
    hwnd: HWND,
    icon: Option<HICON>,
    menu: Option<NativeMenu>,
    mappings: MenuActions,
    events: async_channel::Sender<BackendEvent>,
    snapshot: TraySnapshot,
}

impl WindowsTray {
    pub(crate) fn new(
        snapshot: &TraySnapshot,
        events: async_channel::Sender<BackendEvent>,
    ) -> Result<Self> {
        register_window_class()?;
        let mut state = Box::new(WindowState {
            hwnd: HWND::default(),
            icon: snapshot.icon.as_ref().map(native_icon).transpose()?,
            menu: None,
            mappings: HashMap::new(),
            events,
            snapshot: snapshot.clone(),
        });
        let (menu, mappings) = build_menu(snapshot.menu.as_ref())?;
        state.menu = menu;
        state.mappings = mappings;
        let state_ptr: *mut WindowState = &mut *state;
        // SAFETY: The registered class uses `window_proc`; state is boxed and
        // remains at a stable address until after DestroyWindow returns.
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE::default(),
                w!("gpui-tray-hidden-window-class"),
                w!("gpui-tray"),
                WINDOW_STYLE::default(),
                0,
                0,
                0,
                0,
                None,
                None,
                Some(module_instance()?),
                Some(state_ptr.cast()),
            )
        }
        .map_err(Error::native)?;
        state.hwnd = hwnd;
        state.notify(NIM_ADD)?;
        Ok(Self {
            state,
            closed: false,
        })
    }

    pub(crate) fn apply(&mut self, old: &TraySnapshot, new: &TraySnapshot) -> Result<()> {
        if self.closed {
            return Err(Error::Closed);
        }
        let icon_changed = old.icon != new.icon;
        let menu_changed = old.menu != new.menu;
        let staged_menu = menu_changed
            .then(|| build_menu(new.menu.as_ref()))
            .transpose()?;
        let replacement_icon = if icon_changed {
            Some(new.icon.as_ref().map(native_icon).transpose()?)
        } else {
            None
        };
        let candidate_icon = replacement_icon.unwrap_or(self.state.icon);

        if (icon_changed || old.tooltip != new.tooltip || old.visible != new.visible)
            && let Err(error) = self.state.notify_snapshot(NIM_MODIFY, new, candidate_icon)
        {
            if icon_changed && let Some(icon) = candidate_icon {
                destroy_icon(icon);
            }
            return Err(error);
        }

        let old_icon = icon_changed
            .then(|| std::mem::replace(&mut self.state.icon, candidate_icon))
            .flatten();
        if let Some((menu, mappings)) = staged_menu {
            self.state.menu = menu;
            self.state.mappings = mappings;
        }
        self.state.snapshot = new.clone();
        if let Some(old_icon) = old_icon {
            destroy_icon(old_icon);
        }
        Ok(())
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let delete_result = self.state.notify(NIM_DELETE);
        self.state.cleanup();
        delete_result
    }
}

impl Drop for WindowsTray {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl WindowState {
    fn notify(&self, operation: windows::Win32::UI::Shell::NOTIFY_ICON_MESSAGE) -> Result<()> {
        self.notify_snapshot(operation, &self.snapshot, self.icon)
    }

    fn notify_snapshot(
        &self,
        operation: windows::Win32::UI::Shell::NOTIFY_ICON_MESSAGE,
        snapshot: &TraySnapshot,
        icon: Option<HICON>,
    ) -> Result<()> {
        let mut data = NOTIFYICONDATAW {
            cbSize: u32::try_from(size_of::<NOTIFYICONDATAW>()).expect("size fits u32"),
            hWnd: self.hwnd,
            uID: ICON_ID,
            uFlags: NIF_MESSAGE | NIF_STATE | NIF_ICON | NIF_TIP | NIF_SHOWTIP,
            uCallbackMessage: CALLBACK_MESSAGE,
            hIcon: icon.unwrap_or_default(),
            dwState: if snapshot.visible {
                Default::default()
            } else {
                NIS_HIDDEN
            },
            dwStateMask: NIS_HIDDEN,
            ..Default::default()
        };
        if let Some(tooltip) = snapshot.tooltip.as_deref() {
            copy_utf16(tooltip, &mut data.szTip);
        }
        // SAFETY: `data` has the documented size and references an owned HWND/HICON.
        let succeeded = unsafe { Shell_NotifyIconW(operation, &data) }.as_bool();
        if succeeded {
            Ok(())
        } else {
            Err(Error::native_message(format!(
                "Shell_NotifyIconW operation {} failed",
                operation.0
            )))
        }
    }

    fn cleanup(&mut self) {
        self.mappings.clear();
        self.menu = None;
        if !self.hwnd.is_invalid() {
            // Clear the borrowed Rust pointer even if destroying the window fails.
            // SAFETY: The HWND was created by this state for our registered class.
            unsafe { SetWindowLongPtrW(self.hwnd, GWLP_USERDATA, 0) };
            // SAFETY: The HWND is exclusively owned by this state.
            if let Err(error) = unsafe { DestroyWindow(self.hwnd) } {
                log::warn!("failed to destroy tray window: {error}");
            }
            self.hwnd = HWND::default();
        }
        if let Some(icon) = self.icon.take() {
            destroy_icon(icon);
        }
    }

    fn show_menu(&self) {
        let Some(menu) = self.menu.as_ref() else {
            return;
        };
        // SAFETY: hwnd is a live window owned by this state and the menu is
        // retained for the duration of the synchronous call.
        unsafe {
            let mut point = POINT::default();
            if GetCursorPos(&mut point).is_err() {
                return;
            }
            let _ = SetForegroundWindow(self.hwnd);
            let command = TrackPopupMenu(
                menu.handle,
                TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
                point.x,
                point.y,
                None,
                self.hwnd,
                None,
            )
            .0 as u32;
            if let Some((generation, id)) = self.mappings.get(&command) {
                let _ = self.events.try_send(BackendEvent::MenuItemClicked {
                    generation: *generation,
                    id: *id,
                });
            }
        }
    }
}

impl Drop for WindowState {
    fn drop(&mut self) {
        self.cleanup();
    }
}

struct NativeMenu {
    handle: HMENU,
}

impl NativeMenu {
    fn new() -> Result<Self> {
        // SAFETY: The returned menu is owned by this wrapper.
        let handle = unsafe { CreatePopupMenu() }.map_err(Error::native)?;
        Ok(Self { handle })
    }
}

impl Drop for NativeMenu {
    fn drop(&mut self) {
        // SAFETY: This wrapper owns the menu. DestroyMenu also destroys submenus.
        if let Err(error) = unsafe { DestroyMenu(self.handle) } {
            log::warn!("failed to destroy tray menu: {error}");
        }
    }
}

fn build_menu(snapshot: Option<&MenuSnapshot>) -> Result<(Option<NativeMenu>, MenuActions)> {
    let Some(snapshot) = snapshot else {
        return Ok((None, HashMap::new()));
    };
    let menu = NativeMenu::new()?;
    let mut mappings = HashMap::new();
    let mut next_command = 1;
    append_items(
        menu.handle,
        &snapshot.items,
        snapshot.generation,
        &mut next_command,
        &mut mappings,
    )?;
    Ok((Some(menu), mappings))
}

fn append_items(
    parent: HMENU,
    items: &[NativeMenuItem],
    generation: u64,
    next_command: &mut u32,
    mappings: &mut MenuActions,
) -> Result<()> {
    for item in items {
        match item {
            NativeMenuItem::Separator => {
                // SAFETY: parent is a live menu owned by the caller.
                unsafe { AppendMenuW(parent, MF_SEPARATOR, 0, PCWSTR::null()) }
                    .map_err(Error::native)?;
            }
            NativeMenuItem::Item {
                id,
                label,
                checked,
                enabled,
            } => {
                let command = *next_command;
                *next_command = next_command
                    .checked_add(1)
                    .ok_or_else(|| Error::native_message("too many Windows tray menu items"))?;
                mappings.insert(command, (generation, *id));
                let mut flags = MF_STRING;
                if *checked {
                    flags |= MF_CHECKED;
                }
                if !*enabled {
                    flags |= MF_GRAYED;
                }
                let label = wide_string(label);
                // SAFETY: parent is live and label remains valid for the call.
                unsafe { AppendMenuW(parent, flags, command as usize, PCWSTR(label.as_ptr())) }
                    .map_err(Error::native)?;
            }
            NativeMenuItem::Submenu {
                label,
                enabled,
                items,
            } => {
                let submenu = NativeMenu::new()?;
                append_items(submenu.handle, items, generation, next_command, mappings)?;
                let mut flags = MF_POPUP | MF_STRING;
                if !*enabled {
                    flags |= MF_GRAYED;
                }
                let label = wide_string(label);
                // SAFETY: Both menus are live and label remains valid for the call.
                unsafe {
                    AppendMenuW(
                        parent,
                        flags,
                        submenu.handle.0 as usize,
                        PCWSTR(label.as_ptr()),
                    )
                }
                .map_err(Error::native)?;
                // The parent menu now owns and recursively destroys the submenu.
                std::mem::forget(submenu);
            }
        }
    }
    Ok(())
}

fn wide_string(source: &str) -> Vec<u16> {
    source.encode_utf16().chain(std::iter::once(0)).collect()
}

fn destroy_icon(icon: HICON) {
    // SAFETY: The icon has been removed from state and is no longer used by the shell.
    if let Err(error) = unsafe { DestroyIcon(icon) } {
        log::warn!("failed to destroy tray icon: {error}");
    }
}

fn copy_utf16(source: &str, destination: &mut [u16]) {
    let max = destination.len().saturating_sub(1);
    for (destination, source) in destination.iter_mut().take(max).zip(source.encode_utf16()) {
        *destination = source;
    }
}

fn module_instance() -> Result<HINSTANCE> {
    // SAFETY: None requests the module containing the current process image.
    let module = unsafe { GetModuleHandleW(None) }.map_err(Error::native)?;
    Ok(HINSTANCE(module.0))
}

fn register_window_class() -> Result<()> {
    static REGISTERED: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    REGISTERED
        .get_or_init(|| {
            let class = WNDCLASSW {
                lpfnWndProc: Some(window_proc),
                hInstance: module_instance().map_err(|error| error.to_string())?,
                lpszClassName: w!("gpui-tray-hidden-window-class"),
                ..Default::default()
            };
            // SAFETY: `class` and its static class name remain valid for registration.
            if unsafe { RegisterClassW(&class) } == 0 {
                return Err(windows::core::Error::from_thread().to_string());
            }
            // Register once here so Explorer's restart message ID is available.
            // SAFETY: The string is static and NUL terminated.
            let _ = unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) };
            Ok(())
        })
        .clone()
        .map_err(Error::native_message)
}

fn taskbar_created_message() -> u32 {
    static MESSAGE: OnceLock<u32> = OnceLock::new();
    *MESSAGE.get_or_init(|| {
        // SAFETY: The string is static and NUL terminated.
        unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) }
    })
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        // SAFETY: Windows supplies CREATESTRUCTW for WM_NCCREATE.
        let create = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
        // SAFETY: This stores the stable Box pointer supplied to CreateWindowExW.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, create.lpCreateParams as isize) };
    }
    // SAFETY: We only store WindowState pointers in GWLP_USERDATA for this class.
    let state = unsafe {
        windows::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW(hwnd, GWLP_USERDATA)
            as *mut WindowState
    };
    if !state.is_null() {
        // SAFETY: State remains boxed until after DestroyWindow returns.
        let state = unsafe { &mut *state };
        if message == CALLBACK_MESSAGE {
            let mouse_message = lparam.0 as u32;
            if mouse_message == WM_LBUTTONUP {
                let _ = state.events.try_send(BackendEvent::Activated);
            } else if matches!(mouse_message, WM_RBUTTONUP | WM_CONTEXTMENU) {
                state.show_menu();
            }
            return LRESULT(0);
        }
        if message == taskbar_created_message() {
            let _ = state.notify(NIM_ADD);
            return LRESULT(0);
        }
        if message == WM_CREATE {
            state.hwnd = hwnd;
        } else if message == WM_NCDESTROY {
            // SAFETY: Clearing user data prevents future access to this pointer.
            unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
        }
    }
    // SAFETY: Unhandled messages are forwarded to the default window procedure.
    unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
}

fn native_icon(icon: &Icon) -> Result<HICON> {
    let width = i32::try_from(icon.width())
        .map_err(|_| Error::InvalidIcon("width exceeds i32::MAX".into()))?;
    let height = i32::try_from(icon.height())
        .map_err(|_| Error::InvalidIcon("height exceeds i32::MAX".into()))?;
    let row_bytes = usize::try_from(icon.width())
        .ok()
        .and_then(|width| width.checked_mul(4))
        .ok_or_else(|| Error::InvalidIcon("row byte count overflow".into()))?;
    let mut xor = Vec::with_capacity(icon.rgba().len());
    for row in icon.rgba().chunks_exact(row_bytes).rev() {
        for rgba in row.chunks_exact(4) {
            xor.extend_from_slice(&[rgba[2], rgba[1], rgba[0], rgba[3]]);
        }
    }
    let mask_stride = usize::try_from(icon.width().div_ceil(32))
        .unwrap_or(usize::MAX)
        .saturating_mul(4);
    let and_mask = vec![0_u8; mask_stride.saturating_mul(icon.height() as usize)];
    // SAFETY: Both bit buffers cover the requested dimensions. The 32-bit XOR
    // bitmap is bottom-up BGRA and its alpha channel supplies transparency.
    unsafe { CreateIcon(None, width, height, 1, 32, and_mask.as_ptr(), xor.as_ptr()) }
        .map_err(Error::native)
}

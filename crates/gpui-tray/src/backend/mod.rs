use crate::{Result, menu::MenuItemId, tray::TraySnapshot};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[derive(Clone, Copy, Debug)]
pub(crate) enum BackendEvent {
    Activated,
    MenuItemClicked { generation: u64, id: MenuItemId },
}

pub(crate) struct PlatformTray {
    #[cfg(target_os = "linux")]
    inner: linux::LinuxTray,
    #[cfg(target_os = "macos")]
    inner: macos::MacTray,
    #[cfg(target_os = "windows")]
    inner: windows::WindowsTray,
}

impl PlatformTray {
    pub(crate) fn new(
        snapshot: &TraySnapshot,
        events: async_channel::Sender<BackendEvent>,
    ) -> Result<Self> {
        #[cfg(target_os = "linux")]
        return linux::LinuxTray::new(snapshot, events).map(|inner| Self { inner });
        #[cfg(target_os = "macos")]
        return macos::MacTray::new(snapshot, events).map(|inner| Self { inner });
        #[cfg(target_os = "windows")]
        return windows::WindowsTray::new(snapshot, events).map(|inner| Self { inner });
        #[allow(unreachable_code)]
        Err(crate::Error::UnsupportedPlatform)
    }

    pub(crate) fn apply(&mut self, old: &TraySnapshot, new: &TraySnapshot) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        return self.inner.apply(old, new);
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = (old, new);
            Err(crate::Error::UnsupportedPlatform)
        }
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        return self.inner.close();
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        Err(crate::Error::UnsupportedPlatform)
    }
}

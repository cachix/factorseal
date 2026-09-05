//! Native system tray integration designed specifically for GPUI.
//!
//! Tray menus use [`gpui::MenuItem`] directly and dispatch ordinary GPUI
//! actions. Native backends only receive immutable, platform-neutral snapshots;
//! they never retain or access [`gpui::App`].

mod backend;
mod error;
mod icon;
mod menu;
mod tray;

pub use error::{Error, Result};
pub use icon::Icon;
pub use tray::{Tray, TrayBuilder};

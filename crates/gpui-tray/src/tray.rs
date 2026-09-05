use std::{
    cell::{Cell, RefCell},
    rc::{Rc, Weak},
    thread::{self, ThreadId},
};

use crate::{
    Error, Icon, Result,
    backend::{BackendEvent, PlatformTray},
    menu::{ActionTable, MenuSnapshot, compile_menu},
};

type MenuBuilder = dyn Fn(&mut gpui::App) -> Vec<gpui::MenuItem>;

/// A cloneable handle to a native tray icon.
///
/// `Tray` is intentionally not `Send`: native tray objects and GPUI application
/// state are bound to the thread on which the tray was built.
#[derive(Clone)]
pub struct Tray {
    inner: Rc<TrayInner>,
}

/// Configures and creates a [`Tray`].
#[must_use]
pub struct TrayBuilder {
    icon: Option<Icon>,
    icon_name: Option<String>,
    icon_theme_path: Option<String>,
    title: Option<String>,
    tooltip: Option<String>,
    visible: bool,
    activate_action: Option<Box<dyn gpui::Action>>,
    menu_builder: Option<Box<MenuBuilder>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TraySnapshot {
    pub(crate) icon: Option<Icon>,
    pub(crate) icon_name: Option<String>,
    pub(crate) icon_theme_path: Option<String>,
    pub(crate) title: Option<String>,
    pub(crate) tooltip: Option<String>,
    pub(crate) visible: bool,
    pub(crate) activatable: bool,
    pub(crate) menu: Option<MenuSnapshot>,
}

struct TrayInner {
    thread_id: ThreadId,
    closed: Cell<bool>,
    generation: Cell<u64>,
    snapshot: RefCell<TraySnapshot>,
    actions: RefCell<ActionTable>,
    activate_action: Option<Box<dyn gpui::Action>>,
    menu_builder: Option<Box<MenuBuilder>>,
    backend: RefCell<Option<PlatformTray>>,
}

impl Tray {
    /// Starts building a tray icon.
    pub fn builder() -> TrayBuilder {
        TrayBuilder::default()
    }

    /// Replaces or removes the tray icon.
    pub fn set_icon(&self, icon: Option<Icon>, _cx: &mut gpui::App) -> Result<()> {
        self.inner.update_snapshot(|snapshot| snapshot.icon = icon)
    }

    /// Sets a desktop icon-theme name. Linux shells can recolor names ending in
    /// `-symbolic` to match the system panel; other backends ignore this value.
    pub fn set_icon_name(
        &self,
        icon_name: Option<impl Into<String>>,
        _cx: &mut gpui::App,
    ) -> Result<()> {
        self.inner
            .update_snapshot(|snapshot| snapshot.icon_name = icon_name.map(Into::into))
    }

    /// Sets the directory used to resolve a named icon on Linux.
    pub fn set_icon_theme_path(
        &self,
        icon_theme_path: Option<impl Into<String>>,
        _cx: &mut gpui::App,
    ) -> Result<()> {
        self.inner.update_snapshot(|snapshot| {
            snapshot.icon_theme_path = icon_theme_path.map(Into::into);
        })
    }

    /// Replaces or removes the macOS status-item title.
    pub fn set_title(&self, title: Option<impl Into<String>>, _cx: &mut gpui::App) -> Result<()> {
        self.inner
            .update_snapshot(|snapshot| snapshot.title = title.map(Into::into))
    }

    /// Replaces or removes the native tooltip.
    pub fn set_tooltip(
        &self,
        tooltip: Option<impl Into<String>>,
        _cx: &mut gpui::App,
    ) -> Result<()> {
        self.inner
            .update_snapshot(|snapshot| snapshot.tooltip = tooltip.map(Into::into))
    }

    /// Shows or hides the tray icon.
    pub fn set_visible(&self, visible: bool, _cx: &mut gpui::App) -> Result<()> {
        self.inner
            .update_snapshot(|snapshot| snapshot.visible = visible)
    }

    /// Runs the menu builder against current GPUI state and applies the result.
    pub fn refresh_menu(&self, cx: &mut gpui::App) -> Result<()> {
        self.inner.refresh_menu(cx)
    }

    /// Deterministically removes the tray icon. This method is idempotent.
    pub fn close(&self, _cx: &mut gpui::App) -> Result<()> {
        self.inner.close()
    }
}

impl Default for TrayBuilder {
    fn default() -> Self {
        Self {
            icon: None,
            icon_name: None,
            icon_theme_path: None,
            title: None,
            tooltip: None,
            visible: true,
            activate_action: None,
            menu_builder: None,
        }
    }
}

impl TrayBuilder {
    /// Sets the initial icon.
    pub fn icon(mut self, icon: Icon) -> Self {
        self.icon = Some(icon);
        self
    }

    /// Sets an icon-theme name, such as `example-app-symbolic`, for Linux.
    /// A pixel icon can also be supplied as a fallback for other platforms.
    pub fn icon_name(mut self, icon_name: impl Into<String>) -> Self {
        self.icon_name = Some(icon_name.into());
        self
    }

    /// Sets the Linux icon-theme lookup directory for [`Self::icon_name`].
    pub fn icon_theme_path(mut self, icon_theme_path: impl Into<String>) -> Self {
        self.icon_theme_path = Some(icon_theme_path.into());
        self
    }

    /// Sets the initial status-item title. It is displayed on macOS.
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Sets the initial native tooltip.
    pub fn tooltip(mut self, tooltip: impl Into<String>) -> Self {
        self.tooltip = Some(tooltip.into());
        self
    }

    /// Sets initial visibility. Tray icons are visible by default.
    pub const fn visible(mut self, visible: bool) -> Self {
        self.visible = visible;
        self
    }

    /// Dispatches a GPUI action when the tray icon is primarily activated.
    pub fn on_activate(mut self, action: impl gpui::Action) -> Self {
        self.activate_action = Some(Box::new(action));
        self
    }

    /// Sets the GPUI-aware menu builder.
    pub fn menu(mut self, build: impl Fn(&mut gpui::App) -> Vec<gpui::MenuItem> + 'static) -> Self {
        self.menu_builder = Some(Box::new(build));
        self
    }

    /// Creates the native tray icon and its GPUI event receiver.
    pub fn build(self, cx: &mut gpui::App) -> Result<Tray> {
        let generation = u64::from(self.menu_builder.is_some());
        let (menu, actions) = if let Some(build) = self.menu_builder.as_ref() {
            let (menu, actions) = compile_menu(generation, build(cx))?;
            (Some(menu), actions)
        } else {
            (None, ActionTable::empty(generation))
        };

        let snapshot = TraySnapshot {
            icon: self.icon,
            icon_name: self.icon_name,
            icon_theme_path: self.icon_theme_path,
            title: self.title,
            tooltip: self.tooltip,
            visible: self.visible,
            activatable: self.activate_action.is_some(),
            menu,
        };
        let (events_tx, events_rx) = async_channel::unbounded();
        let backend = PlatformTray::new(&snapshot, events_tx)?;
        let inner = Rc::new(TrayInner {
            thread_id: thread::current().id(),
            closed: Cell::new(false),
            generation: Cell::new(generation),
            snapshot: RefCell::new(snapshot),
            actions: RefCell::new(actions),
            activate_action: self.activate_action,
            menu_builder: self.menu_builder,
            backend: RefCell::new(Some(backend)),
        });

        spawn_event_receiver(cx, Rc::downgrade(&inner), events_rx);
        Ok(Tray { inner })
    }
}

fn spawn_event_receiver(
    cx: &gpui::App,
    inner: Weak<TrayInner>,
    events: async_channel::Receiver<BackendEvent>,
) {
    cx.spawn(async move |cx| {
        while let Ok(event) = events.recv().await {
            let Some(inner) = inner.upgrade() else {
                break;
            };
            cx.update(|cx| inner.handle_event(event, cx));
        }
    })
    .detach();
}

impl TrayInner {
    fn ensure_open_on_creator_thread(&self) -> Result<()> {
        if thread::current().id() != self.thread_id {
            return Err(Error::WrongThread);
        }
        if self.closed.get() {
            return Err(Error::Closed);
        }
        Ok(())
    }

    fn update_snapshot(&self, update: impl FnOnce(&mut TraySnapshot)) -> Result<()> {
        self.ensure_open_on_creator_thread()?;
        let old = self.snapshot.borrow().clone();
        let mut new = old.clone();
        update(&mut new);
        if old == new {
            return Ok(());
        }

        self.backend
            .borrow_mut()
            .as_mut()
            .ok_or(Error::Closed)?
            .apply(&old, &new)?;
        *self.snapshot.borrow_mut() = new;
        Ok(())
    }

    fn refresh_menu(&self, cx: &mut gpui::App) -> Result<()> {
        self.ensure_open_on_creator_thread()?;
        let Some(build) = self.menu_builder.as_ref() else {
            return Ok(());
        };

        let generation = self.generation.get().wrapping_add(1).max(1);
        let (menu, actions) = compile_menu(generation, build(cx))?;
        let old = self.snapshot.borrow().clone();
        let mut new = old.clone();
        new.menu = Some(menu);
        self.backend
            .borrow_mut()
            .as_mut()
            .ok_or(Error::Closed)?
            .apply(&old, &new)?;

        self.generation.set(generation);
        *self.actions.borrow_mut() = actions;
        *self.snapshot.borrow_mut() = new;
        Ok(())
    }

    fn handle_event(&self, event: BackendEvent, cx: &mut gpui::App) {
        if self.closed.get() {
            return;
        }
        match event {
            BackendEvent::Activated => {
                if let Some(action) = self.activate_action.as_ref() {
                    cx.dispatch_action(action.as_ref());
                }
            }
            BackendEvent::MenuItemClicked { generation, id } => {
                let action = {
                    let actions = self.actions.borrow();
                    (actions.generation == generation)
                        .then(|| actions.action(id))
                        .flatten()
                };
                if let Some(action) = action {
                    cx.dispatch_action(action.as_ref());
                    if !self.closed.get()
                        && let Err(error) = self.refresh_menu(cx)
                    {
                        log::error!("failed to refresh tray menu after action: {error}");
                    }
                }
            }
        }
    }

    fn close(&self) -> Result<()> {
        if self.closed.get() {
            return Ok(());
        }
        if thread::current().id() != self.thread_id {
            return Err(Error::WrongThread);
        }

        self.closed.set(true);
        self.backend
            .borrow_mut()
            .take()
            .map_or(Ok(()), |mut backend| backend.close())
    }
}

impl Drop for TrayInner {
    fn drop(&mut self) {
        if let Some(backend) = self.backend.get_mut().as_mut()
            && let Err(error) = backend.close()
        {
            log::error!("failed to close tray while dropping it: {error}");
        }
        self.closed.set(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static_assertions::assert_not_impl_any!(Tray: Send, Sync);

    #[test]
    fn builder_defaults_to_visible() {
        let builder = TrayBuilder::default();
        assert!(builder.visible);
        assert!(builder.icon.is_none());
        assert!(builder.icon_name.is_none());
        assert!(builder.icon_theme_path.is_none());
        assert!(builder.activate_action.is_none());
        assert!(builder.menu_builder.is_none());
    }
}

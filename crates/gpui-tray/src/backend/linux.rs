use std::{
    collections::HashMap,
    sync::{Arc, Mutex, MutexGuard, mpsc},
    thread::{self, JoinHandle},
    time::Duration,
};

use zbus::{
    blocking::{Connection, Proxy},
    zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Str, StructureBuilder},
};

use crate::{
    Error, Result,
    backend::BackendEvent,
    menu::{MenuItemId, MenuSnapshot, NativeMenuItem},
    tray::TraySnapshot,
};

const ITEM_PATH: &str = "/StatusNotifierItem";
const MENU_PATH: &str = "/Menu";
const ITEM_INTERFACE: &str = "org.kde.StatusNotifierItem";
const MENU_INTERFACE: &str = "com.canonical.dbusmenu";
const WATCHER: &str = "org.kde.StatusNotifierWatcher";
const WATCHER_PATH: &str = "/StatusNotifierWatcher";

pub(crate) struct LinuxTray {
    commands: mpsc::Sender<Command>,
    worker: Option<JoinHandle<()>>,
    closed: bool,
}

enum Command {
    Apply {
        snapshot: TraySnapshot,
        reply: mpsc::SyncSender<std::result::Result<(), String>>,
    },
    Close {
        reply: mpsc::SyncSender<std::result::Result<(), String>>,
    },
}

#[derive(Clone)]
struct ServiceState {
    tray: TraySnapshot,
    revision: u32,
    menu: Vec<DbusMenuItem>,
    events: async_channel::Sender<BackendEvent>,
    next_external_id: i32,
}

#[derive(Clone)]
enum DbusMenuItem {
    Separator {
        external_id: i32,
    },
    Item {
        external_id: i32,
        generation: u64,
        id: MenuItemId,
        label: String,
        checked: bool,
        enabled: bool,
    },
    Submenu {
        external_id: i32,
        label: String,
        enabled: bool,
        items: Vec<Self>,
    },
}

#[derive(Clone)]
struct StatusNotifierItem {
    state: Arc<Mutex<ServiceState>>,
}

#[derive(Clone)]
struct DbusMenu {
    state: Arc<Mutex<ServiceState>>,
}

impl LinuxTray {
    pub(crate) fn new(
        snapshot: &TraySnapshot,
        events: async_channel::Sender<BackendEvent>,
    ) -> Result<Self> {
        let (commands_tx, commands_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let snapshot = snapshot.clone();
        let worker = thread::Builder::new()
            .name("gpui-tray-sni".into())
            .spawn(move || worker_main(snapshot, events, commands_rx, ready_tx))
            .map_err(Error::native)?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                commands: commands_tx,
                worker: Some(worker),
                closed: false,
            }),
            Ok(Err(message)) => {
                let _ = worker.join();
                Err(Error::native_message(message))
            }
            Err(error) => {
                let _ = worker.join();
                Err(Error::native(error))
            }
        }
    }

    pub(crate) fn apply(&mut self, _old: &TraySnapshot, new: &TraySnapshot) -> Result<()> {
        if self.closed {
            return Err(Error::Closed);
        }
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        self.commands
            .send(Command::Apply {
                snapshot: new.clone(),
                reply: reply_tx,
            })
            .map_err(Error::native)?;
        reply_rx
            .recv()
            .map_err(Error::native)?
            .map_err(Error::native_message)
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        let result = if self
            .commands
            .send(Command::Close { reply: reply_tx })
            .is_ok()
        {
            reply_rx
                .recv()
                .map_err(Error::native)?
                .map_err(Error::native_message)
        } else {
            Ok(())
        };
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
            && result.is_ok()
        {
            return Err(Error::native_message("SNI worker thread panicked"));
        }
        result
    }
}

impl Drop for LinuxTray {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn worker_main(
    snapshot: TraySnapshot,
    events: async_channel::Sender<BackendEvent>,
    commands: mpsc::Receiver<Command>,
    ready: mpsc::SyncSender<std::result::Result<(), String>>,
) {
    let service_name = format!(
        "org.kde.StatusNotifierItem-{}-{}",
        std::process::id(),
        unique_worker_id()
    );
    let connection = match create_connection(&service_name) {
        Ok(connection) => connection,
        Err(error) => {
            let _ = ready.send(Err(error.to_string()));
            return;
        }
    };

    let (menu, next_external_id) = compile_dbus_menu(snapshot.menu.as_ref(), 1);
    let state = Arc::new(Mutex::new(ServiceState {
        tray: snapshot,
        revision: 1,
        menu,
        events,
        next_external_id,
    }));
    if let Err(error) = connection.object_server().at(
        ITEM_PATH,
        StatusNotifierItem {
            state: state.clone(),
        },
    ) {
        let _ = ready.send(Err(error.to_string()));
        return;
    }
    if let Err(error) = connection.object_server().at(
        MENU_PATH,
        DbusMenu {
            state: state.clone(),
        },
    ) {
        let _ = ready.send(Err(error.to_string()));
        return;
    }

    // A missing watcher is a normal desktop state, not a construction error.
    let _ = register_with_watcher(&connection, &service_name);
    let _ = ready.send(Ok(()));
    let mut watcher_was_present = false;

    loop {
        match commands.recv_timeout(Duration::from_secs(2)) {
            Ok(Command::Apply { snapshot, reply }) => {
                let result = apply_snapshot(&connection, &state, snapshot)
                    .map_err(|error| error.to_string());
                let _ = reply.send(result);
            }
            Ok(Command::Close { reply }) => {
                let result = (|| -> zbus::Result<()> {
                    connection
                        .object_server()
                        .remove::<StatusNotifierItem, _>(ITEM_PATH)?;
                    connection
                        .object_server()
                        .remove::<DbusMenu, _>(MENU_PATH)?;
                    connection.release_name(service_name.as_str())?;
                    Ok(())
                })()
                .map_err(|error| error.to_string());
                let _ = reply.send(result);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let watcher_is_present = watcher_present(&connection).unwrap_or(false);
                if watcher_is_present && !watcher_was_present {
                    let _ = register_with_watcher(&connection, &service_name);
                }
                watcher_was_present = watcher_is_present;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

fn create_connection(service_name: &str) -> zbus::Result<Connection> {
    let connection = Connection::session()?;
    connection.request_name(service_name)?;
    Ok(connection)
}

fn unique_worker_id() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn watcher_present(connection: &Connection) -> zbus::Result<bool> {
    let proxy = Proxy::new(
        connection,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )?;
    proxy.call("NameHasOwner", &(WATCHER))
}

fn register_with_watcher(connection: &Connection, service_name: &str) -> zbus::Result<()> {
    let proxy = Proxy::new(connection, WATCHER, WATCHER_PATH, WATCHER)?;
    proxy.call("RegisterStatusNotifierItem", &(service_name))
}

fn apply_snapshot(
    connection: &Connection,
    state: &Arc<Mutex<ServiceState>>,
    snapshot: TraySnapshot,
) -> zbus::Result<()> {
    let (icon_changed, title_changed, tooltip_changed, status_changed, menu_changed, revision) = {
        let mut state = lock(state);
        let old = &state.tray;
        let changes = (
            old.icon != snapshot.icon
                || old.icon_name != snapshot.icon_name
                || old.icon_theme_path != snapshot.icon_theme_path,
            old.title != snapshot.title,
            old.tooltip != snapshot.tooltip,
            old.visible != snapshot.visible,
            old.menu != snapshot.menu,
        );
        if changes.4 {
            let (menu, next_id) = compile_dbus_menu(snapshot.menu.as_ref(), state.next_external_id);
            state.menu = menu;
            state.next_external_id = next_id;
            state.revision = state.revision.wrapping_add(1).max(1);
        }
        state.tray = snapshot;
        (
            changes.0,
            changes.1,
            changes.2,
            changes.3,
            changes.4,
            state.revision,
        )
    };

    if icon_changed {
        emit_empty_signal(connection, ITEM_PATH, ITEM_INTERFACE, "NewIcon")?;
    }
    if title_changed {
        emit_empty_signal(connection, ITEM_PATH, ITEM_INTERFACE, "NewTitle")?;
    }
    if icon_changed || title_changed || tooltip_changed {
        emit_empty_signal(connection, ITEM_PATH, ITEM_INTERFACE, "NewToolTip")?;
    }
    if status_changed {
        emit_empty_signal(connection, ITEM_PATH, ITEM_INTERFACE, "NewStatus")?;
    }
    if menu_changed {
        connection.emit_signal(
            None::<&str>,
            MENU_PATH,
            MENU_INTERFACE,
            "LayoutUpdated",
            &(revision, 0_i32),
        )?;
    }
    Ok(())
}

fn emit_empty_signal(
    connection: &Connection,
    path: &str,
    interface: &str,
    name: &str,
) -> zbus::Result<()> {
    connection.emit_signal(None::<&str>, path, interface, name, &())
}

fn compile_dbus_menu(
    snapshot: Option<&MenuSnapshot>,
    mut next_id: i32,
) -> (Vec<DbusMenuItem>, i32) {
    fn allocate(next_id: &mut i32) -> i32 {
        let id = *next_id;
        *next_id = next_id.checked_add(1).unwrap_or(1).max(1);
        id
    }

    fn compile(items: &[NativeMenuItem], generation: u64, next_id: &mut i32) -> Vec<DbusMenuItem> {
        items
            .iter()
            .map(|item| match item {
                NativeMenuItem::Separator => DbusMenuItem::Separator {
                    external_id: allocate(next_id),
                },
                NativeMenuItem::Item {
                    id,
                    label,
                    checked,
                    enabled,
                } => DbusMenuItem::Item {
                    external_id: allocate(next_id),
                    generation,
                    id: *id,
                    label: label.clone(),
                    checked: *checked,
                    enabled: *enabled,
                },
                NativeMenuItem::Submenu {
                    label,
                    enabled,
                    items,
                } => DbusMenuItem::Submenu {
                    external_id: allocate(next_id),
                    label: label.clone(),
                    enabled: *enabled,
                    items: compile(items, generation, next_id),
                },
            })
            .collect()
    }

    let menu = snapshot.map_or_else(Vec::new, |snapshot| {
        compile(&snapshot.items, snapshot.generation, &mut next_id)
    });
    (menu, next_id)
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

type Properties = HashMap<String, OwnedValue>;
type Layout = (i32, Properties, Vec<OwnedValue>);
type Pixmap = (i32, i32, Vec<u8>);
type ToolTip = (String, Vec<Pixmap>, String, String);

fn owned_string(value: impl Into<String>) -> OwnedValue {
    OwnedValue::from(Str::from(value.into()))
}

fn item_properties(item: &DbusMenuItem, requested: &[String]) -> Properties {
    let wants = |name: &str| requested.is_empty() || requested.iter().any(|item| item == name);
    let mut properties = HashMap::new();
    match item {
        DbusMenuItem::Separator { .. } => {
            if wants("type") {
                properties.insert("type".into(), owned_string("separator"));
            }
        }
        DbusMenuItem::Item {
            label,
            checked,
            enabled,
            ..
        } => {
            if wants("label") {
                properties.insert("label".into(), owned_string(label.clone()));
            }
            if wants("enabled") {
                properties.insert("enabled".into(), OwnedValue::from(*enabled));
            }
            if *checked && wants("toggle-type") {
                properties.insert("toggle-type".into(), owned_string("checkmark"));
            }
            if *checked && wants("toggle-state") {
                properties.insert("toggle-state".into(), OwnedValue::from(i32::from(*checked)));
            }
        }
        DbusMenuItem::Submenu { label, enabled, .. } => {
            if wants("label") {
                properties.insert("label".into(), owned_string(label.clone()));
            }
            if wants("enabled") {
                properties.insert("enabled".into(), OwnedValue::from(*enabled));
            }
            if wants("children-display") {
                properties.insert("children-display".into(), owned_string("submenu"));
            }
        }
    }
    properties
}

fn item_id(item: &DbusMenuItem) -> i32 {
    match item {
        DbusMenuItem::Separator { external_id }
        | DbusMenuItem::Item { external_id, .. }
        | DbusMenuItem::Submenu { external_id, .. } => *external_id,
    }
}

fn item_children(item: &DbusMenuItem) -> &[DbusMenuItem] {
    match item {
        DbusMenuItem::Submenu { items, .. } => items,
        _ => &[],
    }
}

fn find_item(items: &[DbusMenuItem], id: i32) -> Option<&DbusMenuItem> {
    items.iter().find_map(|item| {
        (item_id(item) == id)
            .then_some(item)
            .or_else(|| find_item(item_children(item), id))
    })
}

fn all_items(items: &[DbusMenuItem]) -> Vec<&DbusMenuItem> {
    fn collect<'a>(items: &'a [DbusMenuItem], output: &mut Vec<&'a DbusMenuItem>) {
        for item in items {
            output.push(item);
            collect(item_children(item), output);
        }
    }

    let mut output = Vec::new();
    collect(items, &mut output);
    output
}

fn layout_value(item: &DbusMenuItem, depth: i32, requested: &[String]) -> OwnedValue {
    let children = if depth == 0 {
        Vec::new()
    } else {
        item_children(item)
            .iter()
            .map(|child| layout_value(child, depth.saturating_sub(1), requested))
            .collect()
    };
    let structure = StructureBuilder::new()
        .add_field(item_id(item))
        .add_field(item_properties(item, requested))
        .add_field(children)
        .build()
        .expect("DBusMenu layout structure is non-empty");
    OwnedValue::try_from(structure).expect("DBusMenu layout contains owned values")
}

fn root_layout(items: &[DbusMenuItem], depth: i32, requested: &[String]) -> Layout {
    let children = if depth == 0 {
        Vec::new()
    } else {
        items
            .iter()
            .map(|item| layout_value(item, depth.saturating_sub(1), requested))
            .collect()
    };
    (0, HashMap::new(), children)
}

fn icon_pixmap(snapshot: &TraySnapshot) -> Vec<Pixmap> {
    let Some(icon) = snapshot.icon.as_ref() else {
        return Vec::new();
    };
    let mut argb = Vec::with_capacity(icon.rgba().len());
    for rgba in icon.rgba().chunks_exact(4) {
        argb.extend_from_slice(&[rgba[3], rgba[0], rgba[1], rgba[2]]);
    }
    vec![(
        i32::try_from(icon.width()).unwrap_or(i32::MAX),
        i32::try_from(icon.height()).unwrap_or(i32::MAX),
        argb,
    )]
}

#[zbus::interface(name = "org.kde.StatusNotifierItem")]
impl StatusNotifierItem {
    fn context_menu(&self, _x: i32, _y: i32) {}

    fn activate(&self, _x: i32, _y: i32) {
        let state = lock(&self.state);
        let _ = state.events.try_send(BackendEvent::Activated);
    }

    fn secondary_activate(&self, _x: i32, _y: i32) {}

    fn scroll(&self, _delta: i32, _orientation: &str) {}

    #[zbus(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }

    #[zbus(property)]
    fn id(&self) -> &str {
        "gpui-tray"
    }

    #[zbus(property)]
    fn title(&self) -> String {
        lock(&self.state).tray.title.clone().unwrap_or_default()
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        if lock(&self.state).tray.visible {
            "Active"
        } else {
            "Passive"
        }
    }

    #[zbus(property)]
    fn window_id(&self) -> u32 {
        0
    }

    #[zbus(property)]
    fn icon_name(&self) -> String {
        lock(&self.state).tray.icon_name.clone().unwrap_or_default()
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> String {
        lock(&self.state)
            .tray
            .icon_theme_path
            .clone()
            .unwrap_or_default()
    }

    #[zbus(property)]
    fn icon_pixmap(&self) -> Vec<Pixmap> {
        icon_pixmap(&lock(&self.state).tray)
    }

    #[zbus(property)]
    fn overlay_icon_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn overlay_icon_pixmap(&self) -> Vec<Pixmap> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_icon_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn attention_icon_pixmap(&self) -> Vec<Pixmap> {
        Vec::new()
    }

    #[zbus(property)]
    fn attention_movie_name(&self) -> &str {
        ""
    }

    #[zbus(property)]
    fn tool_tip(&self) -> ToolTip {
        let state = lock(&self.state);
        (
            state.tray.icon_name.clone().unwrap_or_default(),
            icon_pixmap(&state.tray),
            state.tray.title.clone().unwrap_or_default(),
            state.tray.tooltip.clone().unwrap_or_default(),
        )
    }

    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        !lock(&self.state).tray.activatable
    }

    #[zbus(property)]
    fn menu(&self) -> OwnedObjectPath {
        ObjectPath::try_from(MENU_PATH)
            .expect("constant menu object path is valid")
            .into()
    }
}

#[zbus::interface(name = "com.canonical.dbusmenu")]
impl DbusMenu {
    fn get_layout(
        &self,
        parent_id: i32,
        recursion_depth: i32,
        property_names: Vec<String>,
    ) -> (u32, Layout) {
        let state = lock(&self.state);
        let layout = if parent_id == 0 {
            root_layout(&state.menu, recursion_depth, &property_names)
        } else if let Some(parent) = find_item(&state.menu, parent_id) {
            (
                item_id(parent),
                item_properties(parent, &property_names),
                if recursion_depth == 0 {
                    Vec::new()
                } else {
                    item_children(parent)
                        .iter()
                        .map(|item| {
                            layout_value(item, recursion_depth.saturating_sub(1), &property_names)
                        })
                        .collect()
                },
            )
        } else {
            root_layout(&[], recursion_depth, &property_names)
        };
        (state.revision, layout)
    }

    fn get_group_properties(
        &self,
        ids: Vec<i32>,
        property_names: Vec<String>,
    ) -> Vec<(i32, Properties)> {
        let state = lock(&self.state);
        if ids.is_empty() {
            return all_items(&state.menu)
                .into_iter()
                .map(|item| (item_id(item), item_properties(item, &property_names)))
                .collect();
        }
        ids.into_iter()
            .filter_map(|id| {
                find_item(&state.menu, id).map(|item| (id, item_properties(item, &property_names)))
            })
            .collect()
    }

    fn get_property(&self, id: i32, name: &str) -> zbus::fdo::Result<OwnedValue> {
        let state = lock(&self.state);
        let item = find_item(&state.menu, id)
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("unknown menu item {id}")))?;
        item_properties(item, &[name.to_owned()])
            .remove(name)
            .ok_or_else(|| zbus::fdo::Error::Failed(format!("unknown menu property {name}")))
    }

    fn event(&self, id: i32, event_id: &str, _data: OwnedValue, _timestamp: u32) {
        if event_id != "clicked" {
            return;
        }
        let state = lock(&self.state);
        let Some(DbusMenuItem::Item {
            generation,
            id,
            enabled: true,
            ..
        }) = find_item(&state.menu, id)
        else {
            return;
        };
        let _ = state.events.try_send(BackendEvent::MenuItemClicked {
            generation: *generation,
            id: *id,
        });
    }

    fn event_group(&self, events: Vec<(i32, String, OwnedValue, u32)>) -> Vec<i32> {
        for (id, event, data, timestamp) in events {
            self.event(id, &event, data, timestamp);
        }
        Vec::new()
    }

    fn about_to_show(&self, _id: i32) -> bool {
        false
    }

    fn about_to_show_group(&self, _ids: Vec<i32>) -> (Vec<i32>, Vec<i32>) {
        (Vec::new(), Vec::new())
    }

    #[zbus(property)]
    fn version(&self) -> u32 {
        3
    }

    #[zbus(property)]
    fn text_direction(&self) -> &str {
        "ltr"
    }

    #[zbus(property)]
    fn status(&self) -> &str {
        "normal"
    }

    #[zbus(property)]
    fn icon_theme_path(&self) -> Vec<String> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rgba_is_converted_to_argb() {
        let icon = crate::Icon::from_rgba(vec![1, 2, 3, 4], 1, 1).unwrap();
        let snapshot = TraySnapshot {
            icon: Some(icon),
            icon_name: None,
            icon_theme_path: None,
            title: None,
            tooltip: None,
            visible: true,
            activatable: false,
            menu: None,
        };
        assert_eq!(icon_pixmap(&snapshot)[0].2, vec![4, 1, 2, 3]);
    }

    #[test]
    fn empty_group_property_ids_select_every_item_recursively() {
        let menu = vec![DbusMenuItem::Submenu {
            external_id: 1,
            label: "Parent".into(),
            enabled: true,
            items: vec![DbusMenuItem::Item {
                external_id: 2,
                generation: 1,
                id: MenuItemId(7),
                label: "Child".into(),
                checked: false,
                enabled: true,
            }],
        }];

        assert_eq!(
            all_items(&menu)
                .into_iter()
                .map(item_id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
    }
}

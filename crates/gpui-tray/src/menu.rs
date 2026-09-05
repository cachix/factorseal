use std::collections::HashMap;

use crate::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MenuSnapshot {
    pub(crate) generation: u64,
    pub(crate) items: Vec<NativeMenuItem>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NativeMenuItem {
    Separator,
    Item {
        id: MenuItemId,
        label: String,
        checked: bool,
        enabled: bool,
    },
    Submenu {
        label: String,
        enabled: bool,
        items: Vec<Self>,
    },
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
pub(crate) struct MenuItemId(pub(crate) u32);

pub(crate) struct ActionTable {
    pub(crate) generation: u64,
    actions: HashMap<MenuItemId, Box<dyn gpui::Action>>,
}

impl ActionTable {
    pub(crate) fn empty(generation: u64) -> Self {
        Self {
            generation,
            actions: HashMap::new(),
        }
    }

    pub(crate) fn action(&self, id: MenuItemId) -> Option<Box<dyn gpui::Action>> {
        self.actions.get(&id).map(|action| action.boxed_clone())
    }
}

pub(crate) fn compile_menu(
    generation: u64,
    items: Vec<gpui::MenuItem>,
) -> Result<(MenuSnapshot, ActionTable)> {
    let mut next_id = 1_u32;
    let mut actions = HashMap::new();
    let items = compile_items(items, &mut next_id, &mut actions)?;

    Ok((
        MenuSnapshot { generation, items },
        ActionTable {
            generation,
            actions,
        },
    ))
}

fn compile_items(
    items: Vec<gpui::MenuItem>,
    next_id: &mut u32,
    actions: &mut HashMap<MenuItemId, Box<dyn gpui::Action>>,
) -> Result<Vec<NativeMenuItem>> {
    items
        .into_iter()
        .map(|item| {
            let checked = menu_item_checked(&item);
            let enabled = menu_item_enabled(&item);
            match item {
                gpui::MenuItem::Separator => Ok(NativeMenuItem::Separator),
                gpui::MenuItem::Submenu(menu) => Ok(NativeMenuItem::Submenu {
                    label: menu.name.to_string(),
                    enabled,
                    items: compile_items(menu.items, next_id, actions)?,
                }),
                gpui::MenuItem::Action { name, action, .. } => {
                    let id = MenuItemId(*next_id);
                    *next_id = next_id.checked_add(1).ok_or_else(|| {
                        Error::native_message("tray menu contains more than u32::MAX actions")
                    })?;
                    actions.insert(id, action);
                    Ok(NativeMenuItem::Item {
                        id,
                        label: name.to_string(),
                        checked,
                        enabled,
                    })
                }
                gpui::MenuItem::SystemMenu(_) => Err(Error::UnsupportedMenuItem("SystemMenu")),
            }
        })
        .collect()
}

#[cfg(feature = "menu-state")]
fn menu_item_checked(item: &gpui::MenuItem) -> bool {
    item.is_checked()
}

#[cfg(not(feature = "menu-state"))]
fn menu_item_checked(_item: &gpui::MenuItem) -> bool {
    false
}

#[cfg(feature = "menu-state")]
fn menu_item_enabled(item: &gpui::MenuItem) -> bool {
    !item.is_disabled()
}

#[cfg(not(feature = "menu-state"))]
fn menu_item_enabled(_item: &gpui::MenuItem) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    gpui::actions!(test, [First, Second]);

    #[test]
    fn compiles_nested_menu_and_actions() {
        #[cfg(feature = "menu-state")]
        let items = vec![
            gpui::MenuItem::action("First", First).checked(true),
            gpui::MenuItem::separator(),
            gpui::MenuItem::submenu(gpui::Menu {
                name: "Nested".into(),
                items: vec![gpui::MenuItem::action("Second", Second).disabled(true)],
                disabled: false,
            }),
        ];
        #[cfg(not(feature = "menu-state"))]
        let items = vec![
            gpui::MenuItem::action("First", First),
            gpui::MenuItem::separator(),
            gpui::MenuItem::submenu(gpui::Menu {
                name: "Nested".into(),
                items: vec![gpui::MenuItem::action("Second", Second)],
                disabled: false,
            }),
        ];

        let (snapshot, table) = compile_menu(7, items).unwrap();
        assert_eq!(snapshot.generation, 7);
        assert_eq!(table.generation, 7);
        assert!(table.action(MenuItemId(1)).is_some());
        assert!(table.action(MenuItemId(2)).is_some());
        assert!(table.action(MenuItemId(3)).is_none());
        let NativeMenuItem::Item {
            checked, enabled, ..
        } = &snapshot.items[0]
        else {
            panic!("first compiled item is not an action");
        };
        assert_eq!(*checked, cfg!(feature = "menu-state"));
        assert!(*enabled);
    }
}

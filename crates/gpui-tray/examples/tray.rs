//! A windowless GPUI application demonstrating `gpui-tray`.
#![allow(missing_docs)]

use gpui::{App, Global, Menu, MenuItem, NoAction, QuitMode, actions};
use gpui_tray::{Icon, Tray};

actions!(
    tray_example,
    [SelectList, SelectGrid, ToggleCounter, Increment, Quit,]
);

#[derive(Clone, Copy, PartialEq, Eq)]
enum ViewMode {
    List,
    Grid,
}

struct ExampleState {
    mode: ViewMode,
    counter_enabled: bool,
    count: u32,
}

impl Global for ExampleState {}

struct ExampleTray(Tray);

impl Global for ExampleTray {}

fn main() {
    gpui_platform::application()
        // This example deliberately has no window, so it must only quit from
        // the tray menu rather than when the last window closes.
        .with_quit_mode(QuitMode::Explicit)
        .run(|cx: &mut App| {
            if let Err(error) = setup(cx) {
                eprintln!("failed to create tray example: {error}");
                cx.quit();
            }
        });
}

fn setup(cx: &mut App) -> gpui_tray::Result<()> {
    cx.set_global(ExampleState {
        mode: ViewMode::List,
        counter_enabled: true,
        count: 0,
    });

    cx.on_action(select_list)
        .on_action(select_grid)
        .on_action(toggle_counter)
        .on_action(increment)
        .on_action(quit);

    let tray = Tray::builder()
        .icon(example_icon()?)
        .title("GPUI Tray")
        .tooltip("gpui-tray example")
        .menu(build_menu)
        .build(cx)?;
    cx.set_global(ExampleTray(tray));

    println!("gpui-tray example is running; use the tray menu to interact or quit.");
    Ok(())
}

fn build_menu(cx: &mut App) -> Vec<MenuItem> {
    let state = cx.global::<ExampleState>();
    let mode = state.mode;
    let counter_enabled = state.counter_enabled;
    let count = state.count;

    vec![
        disabled(
            MenuItem::action(format!("Counter: {count}"), NoAction),
            true,
        ),
        disabled(
            MenuItem::action("Increment counter", Increment),
            !counter_enabled,
        ),
        checked(
            MenuItem::action("Counter enabled", ToggleCounter),
            counter_enabled,
        ),
        MenuItem::separator(),
        MenuItem::submenu(Menu::new("View mode").items([
            checked(MenuItem::action("List", SelectList), mode == ViewMode::List),
            checked(MenuItem::action("Grid", SelectGrid), mode == ViewMode::Grid),
        ])),
        MenuItem::separator(),
        MenuItem::action("Quit", Quit),
    ]
}

#[cfg(feature = "menu-state")]
fn checked(item: MenuItem, checked: bool) -> MenuItem {
    item.checked(checked)
}

#[cfg(not(feature = "menu-state"))]
fn checked(item: MenuItem, _checked: bool) -> MenuItem {
    item
}

#[cfg(feature = "menu-state")]
fn disabled(item: MenuItem, disabled: bool) -> MenuItem {
    item.disabled(disabled)
}

#[cfg(not(feature = "menu-state"))]
fn disabled(item: MenuItem, _disabled: bool) -> MenuItem {
    item
}

fn select_list(_: &SelectList, cx: &mut App) {
    cx.global_mut::<ExampleState>().mode = ViewMode::List;
    println!("view mode: list");
}

fn select_grid(_: &SelectGrid, cx: &mut App) {
    cx.global_mut::<ExampleState>().mode = ViewMode::Grid;
    println!("view mode: grid");
}

fn toggle_counter(_: &ToggleCounter, cx: &mut App) {
    let state = cx.global_mut::<ExampleState>();
    state.counter_enabled = !state.counter_enabled;
    println!("counter enabled: {}", state.counter_enabled);
}

fn increment(_: &Increment, cx: &mut App) {
    let state = cx.global_mut::<ExampleState>();
    state.count = state.count.saturating_add(1);
    println!("counter: {}", state.count);
}

fn quit(_: &Quit, cx: &mut App) {
    let tray = cx.global::<ExampleTray>().0.clone();
    if let Err(error) = tray.close(cx) {
        eprintln!("failed to close tray: {error}");
    }
    cx.quit();
}

fn example_icon() -> gpui_tray::Result<Icon> {
    const SIZE: u32 = 32;
    let mut rgba = vec![0_u8; (SIZE * SIZE * 4) as usize];

    for y in 0..SIZE {
        for x in 0..SIZE {
            let offset = ((y * SIZE + x) * 4) as usize;
            let dx = x as i32 - 15;
            let dy = y as i32 - 15;
            let inside_circle = dx * dx + dy * dy <= 14 * 14;
            let inside_t = (8..=23).contains(&x) && (8..=12).contains(&y)
                || (14..=17).contains(&x) && (8..=24).contains(&y);

            if inside_t {
                rgba[offset..offset + 4].copy_from_slice(&[255, 255, 255, 255]);
            } else if inside_circle {
                rgba[offset..offset + 4].copy_from_slice(&[45, 105, 220, 255]);
            }
        }
    }

    Icon::from_rgba(rgba, SIZE, SIZE)
}

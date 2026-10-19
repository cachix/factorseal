use std::collections::{HashMap, HashSet};

use gpui::{Pixels, ScrollHandle, point};
use gpui_component::progress::ProgressCircle;

use super::item_editor::{Draft, EditStart};
use super::personal_history::{Change, Direction, Step};
use super::totp::{Totp, grouped, unix_now};
use super::*;
use crate::runtime::{ItemVersion, PersonalWriteError};

pub(super) struct ChangeToast {
    pub(super) id: u64,
    pub(super) message: gpui::SharedString,
    pub(super) undo: Option<Direction>,
    pub(super) error: bool,
    pub(super) leaving: bool,
}

#[derive(Default)]
pub(super) struct PersonalDetail {
    item: Option<PersonalSecret>,
    version: Option<ItemVersion>,
    error: Option<String>,
    revealed: HashSet<usize>,
    scroll: ScrollHandle,
    generation: u64,
    inputs: HashMap<usize, gpui::Entity<SecretInputState>>,
    ticker: Option<Task<()>>,
    loaded_at: Option<std::time::Instant>,
}

impl PersonalDetail {
    pub(super) fn item(&self) -> Option<&PersonalSecret> {
        self.item.as_ref()
    }

    pub(super) fn revealed(&self) -> &HashSet<usize> {
        &self.revealed
    }

    pub(super) fn scroll_handle(&self) -> ScrollHandle {
        self.scroll.clone()
    }

    pub(super) fn clear_error(&mut self) {
        self.error = None;
    }

    pub(super) fn has_value(&self, index: usize) -> bool {
        self.item.as_ref().is_some_and(|item| {
            item.sections
                .iter()
                .flat_map(|section| &section.fields)
                .nth(index)
                .is_some_and(|field| !field_is_empty(field))
        })
    }

    pub(super) fn clear(&mut self) {
        self.inputs.clear();
        self.item = None;
        self.version = None;
        self.error = None;
        self.revealed.clear();
        self.scroll.set_offset(point(px(0.), px(0.)));
        self.ticker = None;
        self.loaded_at = None;
        self.generation = self.generation.wrapping_add(1);
    }
}

pub(super) fn offset_showing(
    offset: Pixels,
    max_offset: Pixels,
    viewport: Bounds<Pixels>,
    target: Bounds<Pixels>,
) -> Pixels {
    let above = viewport.top() - target.top();
    let below = target.bottom() - viewport.bottom();
    let shift = if above > px(0.) {
        above
    } else if below > px(0.) {
        -below.min(-above)
    } else {
        px(0.)
    };
    (offset + shift).clamp(-max_offset, px(0.))
}

fn field_text(field: &PersonalField, revealed: bool) -> String {
    if field.is_concealed() && !revealed {
        "••••••••".into()
    } else {
        field.text().map_or_else(
            || serde_json::to_string_pretty(&field.value).unwrap_or_default(),
            ToOwned::to_owned,
        )
    }
}

pub(super) fn field_is_empty(field: &PersonalField) -> bool {
    field.value.is_null() || field.text().is_some_and(str::is_empty)
}

fn has_section_groups(item: &PersonalSecret) -> bool {
    item.sections
        .iter()
        .filter(|section| section.fields.iter().any(|field| !field_is_empty(field)))
        .count()
        > 1
}

fn section_heading<'a>(item: &PersonalSecret, section: &'a PersonalSection) -> Option<&'a str> {
    (!section.label.eq_ignore_ascii_case(item.kind.label())).then_some(section.label.as_str())
}

fn has_one_time_code(item: &PersonalSecret) -> bool {
    item.sections
        .iter()
        .flat_map(|section| &section.fields)
        .filter(|field| field.field_type == PersonalFieldType::Totp)
        .filter_map(PersonalField::text)
        .any(|value| Totp::parse(value).is_some())
}

fn website_url(value: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with("https://") || value.starts_with("http://") {
        Some(value.to_owned())
    } else if !value.contains("://") && value.contains('.') && !value.contains(char::is_whitespace)
    {
        Some(format!("https://{value}"))
    } else {
        None
    }
}

fn modified_text(updated_at: u64, zone: &jiff::tz::TimeZone) -> Option<String> {
    let seconds = i64::try_from(updated_at)
        .ok()
        .filter(|seconds| *seconds > 0)?;
    let timestamp = jiff::Timestamp::from_second(seconds).ok()?;
    Some(format!(
        "Modified {}",
        timestamp.to_zoned(zone.clone()).strftime("%-d %B %Y")
    ))
}

pub(super) const CONTENT_WIDTH: gpui::Rems = rems(48.);
const OPEN_PATIENCE: std::time::Duration = std::time::Duration::from_millis(150);
const PERSONAL_TOAST_LIFETIME: std::time::Duration = std::time::Duration::from_secs(5);
pub(super) const ITEM_CHANGED: &str =
    "This item changed somewhere else, so your change was not saved.";

pub(super) fn copied_item(item: &PersonalSecret) -> Result<PersonalSecret, String> {
    let encoded = item.encode().map_err(|error| error.to_string())?;
    PersonalSecret::decode_current(&encoded).map_err(|error| error.to_string())
}

fn favorite_item(item: &PersonalSecret, favorite: bool) -> Result<PersonalSecret, String> {
    let mut updated = copied_item(item)?;
    updated.favorite = favorite;
    Ok(updated)
}

#[derive(Debug, PartialEq)]
enum Reopen<'a> {
    Item(&'a factorseal::VaultEntryMetadata),
    List,
    Stay,
}

fn reopen_after<'a>(
    direction: Direction,
    id: &str,
    open: bool,
    entries: &'a [factorseal::VaultEntryMetadata],
) -> Reopen<'a> {
    let restored = entries
        .iter()
        .find(|entry| personal_item_id(entry) == Some(id))
        .filter(|_| direction == Direction::Undo);
    match restored {
        Some(entry) => Reopen::Item(entry),
        None if open => Reopen::List,
        None => Reopen::Stay,
    }
}

impl DesktopView {
    pub(super) fn open_personal_entry(
        &mut self,
        entry: factorseal::VaultEntryMetadata,
        cx: &mut Context<Self>,
    ) {
        let showing = self.personal_detail.item.is_some()
            && matches!(
                &self.selected_vault_item,
                Some(VaultSelection::Entry(current)) if current.address == entry.address
            );
        if showing {
            self.selected_vault_item = Some(VaultSelection::Entry(Box::new(entry.clone())));
            self.remember_page(cx);
            self.load_personal_item(entry, cx);
            cx.notify();
            return;
        }
        let Snapshot::Unsealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let metadata = metadata.clone();
        self.follow_opened_entry(&entry.address, cx);
        self.opening = self.opening.wrapping_add(1);
        let ticket = self.opening;
        let runtime = Arc::clone(&self.runtime);
        let read_entry = entry.clone();
        cx.spawn(async move |view, cx| {
            let mut read =
                smol::unblock(move || runtime.read_personal_item(&metadata, &read_entry));
            let early = smol::future::or(async { Some((&mut read).await) }, async {
                smol::Timer::after(OPEN_PATIENCE).await;
                None
            })
            .await;
            let landed = early.is_some();
            let opened = view.update(cx, |view, cx| {
                (view.opening == ticket && view.is_unsealed()).then(|| {
                    view.show_vault_item(VaultSelection::Entry(Box::new(entry)), cx);
                    if let Some(result) = early {
                        view.land_personal_item(result, false, cx);
                    }
                    view.personal_detail.generation
                })
            });
            let (Ok(Some(generation)), false) = (opened, landed) else {
                return;
            };
            let result = read.await;
            let _ = view.update(cx, |view, cx| {
                if view.personal_detail.generation == generation && view.is_unsealed() {
                    view.land_personal_item(result, true, cx);
                }
            });
        })
        .detach();
    }

    pub(super) fn open_saved_personal_item(
        &mut self,
        entry: factorseal::VaultEntryMetadata,
        item: PersonalSecret,
        version: ItemVersion,
        cx: &mut Context<Self>,
    ) {
        self.show_vault_item(VaultSelection::Entry(Box::new(entry)), cx);
        self.land_personal_item(Ok((item, version)), false, cx);
    }

    pub(super) fn load_personal_item(
        &mut self,
        entry: factorseal::VaultEntryMetadata,
        cx: &mut Context<Self>,
    ) {
        let Snapshot::Unsealed { metadata, .. } = &self.snapshot else {
            return;
        };
        let metadata = metadata.clone();
        self.follow_opened_entry(&entry.address, cx);
        let runtime = Arc::clone(&self.runtime);
        let generation = self.personal_detail.generation;
        cx.spawn(async move |view, cx| {
            let result = smol::unblock(move || runtime.read_personal_item(&metadata, &entry)).await;
            let _ = view.update(cx, |view, cx| {
                // Navigation or sealing invalidates an in-flight read.
                if view.personal_detail.generation == generation && view.is_unsealed() {
                    view.land_personal_item(result, false, cx);
                }
            });
        })
        .detach();
    }

    fn land_personal_item(
        &mut self,
        result: Result<(PersonalSecret, ItemVersion), String>,
        fade: bool,
        cx: &mut Context<Self>,
    ) {
        match result {
            Ok((item, version)) => {
                if fade && self.personal_detail.item.is_none() {
                    self.personal_detail.loaded_at = Some(std::time::Instant::now());
                }
                self.personal_detail.inputs.clear();
                self.initialize_personal_inputs(&item, cx);
                self.personal_detail.item = Some(item);
                self.personal_detail.version = Some(version);
                self.update_personal_ticker(cx);
            }
            Err(error) => self.personal_detail.error = Some(error),
        }
        cx.notify();
    }

    pub(super) fn update_personal_ticker(&mut self, cx: &mut Context<Self>) {
        let ticking = self
            .personal_detail
            .item
            .as_ref()
            .is_some_and(has_one_time_code)
            || self.editor_has_code(cx);
        if !ticking {
            self.personal_detail.ticker = None;
            return;
        }
        if self.personal_detail.ticker.is_some() {
            return;
        }
        let generation = self.personal_detail.generation;
        self.personal_detail.ticker = Some(cx.spawn(async move |view, cx| {
            loop {
                smol::Timer::after(std::time::Duration::from_secs(1)).await;
                let ticking = view.update(cx, |view, cx| {
                    let current = view.personal_detail.generation == generation;
                    if current {
                        cx.notify();
                    }
                    current
                });
                if !matches!(ticking, Ok(true)) {
                    break;
                }
            }
        }));
    }

    pub(super) fn render_personal_item(
        &self,
        entry: &factorseal::VaultEntryMetadata,
        cx: &mut Context<Self>,
    ) -> Div {
        let scroll = &self.personal_detail.scroll;
        div()
            .size_full()
            .relative()
            .child(
                div()
                    .id("personal-item-scroll")
                    .size_full()
                    .flex()
                    .flex_col()
                    .overflow_y_scroll()
                    .track_scroll(scroll)
                    .child(self.render_personal_item_content(entry, cx).flex_none()),
            )
            .vertical_scrollbar(scroll)
    }

    pub(super) fn render_new_item_page(&self, cx: &mut Context<Self>) -> Div {
        let scroll = &self.personal_detail.scroll;
        div()
            .size_full()
            .relative()
            .child(
                div()
                    .id("personal-new-item-scroll")
                    .size_full()
                    .flex()
                    .flex_col()
                    .overflow_y_scroll()
                    .track_scroll(scroll)
                    .child(self.render_new_item(cx).flex_none()),
            )
            .vertical_scrollbar(scroll)
    }

    #[allow(clippy::too_many_lines)]
    fn render_personal_item_content(
        &self,
        entry: &factorseal::VaultEntryMetadata,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let (title, kind) = vault_entry_label(entry);
        let editing = self.editing_item();
        let actions = if editing {
            Some(Self::render_editor_buttons(cx))
        } else {
            self.personal_detail.item.as_ref().map(|_| {
                h_flex()
                    .flex_none()
                    .ml_auto()
                    .gap_2()
                    .child(
                        button("edit-personal-item")
                            .icon(Glyph::Pencil)
                            .label("Edit")
                            .on_click(cx.listener(|view, _, window, cx| {
                                view.begin_edit(EditStart::Top, window, cx);
                            })),
                    )
                    .child(Self::render_personal_more(cx))
            })
        };
        let mut panel = v_flex()
            .w_full()
            .max_w(CONTENT_WIDTH)
            .mx_auto()
            .gap_6()
            .p_6()
            .child(
                h_flex()
                    .items_center()
                    .gap_5()
                    .child(personal_entry_icon(
                        entry,
                        self.website_icons.icon(entry),
                        56. / 16.,
                        &theme,
                    ))
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_1()
                            .child(
                                h_flex()
                                    .min_w_0()
                                    .items_center()
                                    .gap_2()
                                    .map(|row| {
                                        if editing {
                                            row.child(self.render_editor_title(cx))
                                        } else {
                                            row.child(
                                                div()
                                                    .min_w_0()
                                                    .text_title()
                                                    .font_semibold()
                                                    .truncate()
                                                    .child(title),
                                            )
                                        }
                                    })
                                    .when_some(
                                        self.personal_detail.item.as_ref().filter(|_| !editing),
                                        |row, item| {
                                            row.child(
                                                button("toggle-personal-favorite")
                                                    .ghost()
                                                    .flex_none()
                                                    .icon(if item.favorite {
                                                        IconName::StarFill
                                                    } else {
                                                        IconName::Star
                                                    })
                                                    .tooltip(if item.favorite {
                                                        "Remove from favorites"
                                                    } else {
                                                        "Add to favorites"
                                                    })
                                                    .on_click(cx.listener(|view, _, _, cx| {
                                                        view.toggle_personal_favorite(cx);
                                                    })),
                                            )
                                        },
                                    ),
                            )
                            .child(
                                div()
                                    .text_body()
                                    .text_color(theme.muted_foreground)
                                    .child(kind),
                            ),
                    )
                    .children(actions.map(|actions| {
                        crate::motion::fade(
                            if editing {
                                "item-edit-actions"
                            } else {
                                "item-view-actions"
                            },
                            actions,
                        )
                    })),
            );
        if let Some(error) = &self.personal_detail.error {
            panel = panel.child(error_banner(error.clone(), theme.danger));
        }
        let Some(item) = &self.personal_detail.item else {
            return panel.child(crate::motion::after_a_moment(
                ("personal-item-loading", self.personal_detail.generation),
                h_flex()
                    .gap_2()
                    .child(Spinner::new().small())
                    .child("Loading item…"),
            ));
        };
        if editing {
            return panel.child(self.render_item_editor(cx));
        }
        let grouped = has_section_groups(item);
        let mut fields = v_flex().w_full().gap_4();
        let mut index = 0;
        for section in &item.sections {
            let mut rows = Vec::new();
            for field in &section.fields {
                if !field_is_empty(field) {
                    rows.push(self.render_personal_value(index, &field.label, Some(field), cx));
                }
                index += 1;
            }
            if !rows.is_empty() {
                let heading = section_heading(item, section)
                    .filter(|_| grouped)
                    .map(|heading| heading.to_owned().into());
                fields = fields.child(item_editor::field_group(heading, rows, cx));
            }
        }
        if item.notes.as_deref().is_some_and(|notes| !notes.is_empty()) {
            fields = fields.child(item_editor::field_group(
                None,
                [self.render_personal_value(index, "Notes", None, cx)],
                cx,
            ));
        }
        panel = panel.child(
            v_flex()
                .w_full()
                .gap_4()
                .map(|panel| {
                    let fresh = self
                        .personal_detail
                        .loaded_at
                        .is_some_and(|loaded| loaded.elapsed() < crate::motion::SETTLE);
                    if fresh {
                        panel.child(crate::motion::fade(
                            ("personal-item-fields", self.personal_detail.generation),
                            fields,
                        ))
                    } else {
                        panel.child(fields)
                    }
                })
                .child(h_flex().child(Self::render_editor_add_field(
                    Draft::from_item(item, |_| ()).addable(),
                    cx,
                ))),
        );
        if let Some(modified) = entry
            .updated_at
            .and_then(|updated_at| modified_text(updated_at, &jiff::tz::TimeZone::system()))
        {
            panel = panel.child(
                div()
                    .px_1()
                    .text_caption()
                    .text_color(theme.muted_foreground)
                    .child(modified),
            );
        }
        panel
    }

    fn initialize_personal_inputs(&mut self, item: &PersonalSecret, cx: &mut Context<Self>) {
        let mut index = 0;
        for field in item.sections.iter().flat_map(|section| &section.fields) {
            let value = Zeroizing::new(field_text(field, true));
            let masked = field.is_concealed() && !self.personal_detail.revealed.contains(&index);
            self.add_personal_input(index, &value, masked, cx);
            index += 1;
        }
        let masked = !self.personal_detail.revealed.contains(&index);
        self.add_personal_input(index, item.notes.as_deref().unwrap_or_default(), masked, cx);
    }

    fn add_personal_input(
        &mut self,
        index: usize,
        value: &str,
        masked: bool,
        cx: &mut Context<Self>,
    ) {
        let input = cx.new(|cx| {
            let mut input = SecretInputState::read_only(cx).masked(masked);
            input.replace(value, cx);
            input
        });
        self.personal_detail.inputs.insert(index, input);
    }

    fn saved_personal_value(&self, index: usize) -> Option<Zeroizing<String>> {
        let item = self.personal_detail.item.as_ref()?;
        let fields: Vec<_> = item
            .sections
            .iter()
            .flat_map(|section| &section.fields)
            .collect();
        Some(Zeroizing::new(match fields.get(index) {
            Some(field) => field_text(field, true),
            None => item.notes.clone().unwrap_or_default(),
        }))
    }

    pub(super) fn apply_personal_contents(&mut self, updated_contents: VaultContents) {
        if let Some(entry) = updated_contents
            .entries
            .iter()
            .find(|entry| is_selected_entry(self.selected_vault_item.as_ref(), entry))
        {
            self.selected_vault_item = Some(VaultSelection::Entry(Box::new(entry.clone())));
        }
        if let Snapshot::Unsealed {
            contents,
            contents_error,
            ..
        } = &mut self.snapshot
        {
            *contents = updated_contents;
            *contents_error = None;
        }
    }

    pub(super) fn save_personal_item(
        &mut self,
        updated: PersonalSecret,
    ) -> Result<(), PersonalWriteError> {
        let (version, contents) = self
            .runtime
            .put_personal_secret(&updated, self.personal_detail.version)?;
        self.apply_personal_contents(contents);
        if let Some(previous) = self.personal_detail.item.replace(updated) {
            self.personal_history.record(Change::Edit {
                item: previous,
                version,
            });
        }
        self.personal_detail.version = Some(version);
        Ok(())
    }

    fn show_changed_item(&mut self, contents: VaultContents, cx: &mut Context<Self>) {
        self.apply_personal_contents(contents);
        self.personal_history.clear();
        if let Some(VaultSelection::Entry(entry)) = self.selected_vault_item.clone()
            && is_personal_secret(&entry)
        {
            let exists = self.unsealed_contents().is_some_and(|contents| {
                contents
                    .entries
                    .iter()
                    .any(|current| current.address == entry.address)
            });
            if exists {
                self.select_vault_item(VaultSelection::Entry(entry), cx);
            } else {
                self.clear_personal_detail();
                self.show_personal_panel(PersonalPanel::Overview, cx);
            }
        }
        self.show_toast(ITEM_CHANGED, None, true, cx);
    }

    pub(super) fn reset_personal_inputs(&mut self, cx: &mut Context<Self>) {
        self.personal_detail.inputs.clear();
        self.personal_detail.revealed.clear();
        if let Some(item) = self.personal_detail.item.take() {
            self.initialize_personal_inputs(&item, cx);
            self.personal_detail.item = Some(item);
        }
        self.update_personal_ticker(cx);
        cx.notify();
    }

    fn confirm_delete_personal_item(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        let title = format!("Delete {}?", item.title);
        let view = cx.weak_entity();
        let overlay = Rc::clone(&self.shortcuts.overlay);
        overlay.set(true);
        window.open_dialog(cx, move |dialog, _, _| {
            let view = view.clone();
            let overlay = Rc::clone(&overlay);
            dialog
                .on_close(move |_, _, _| overlay.set(false))
                .title(title.clone())
                .width(px(420.))
                .close_button(false)
                .child(div().text_body().child("You can undo this right after."))
                .footer(
                    DialogFooter::new()
                        .child(
                            button("cancel-delete-personal-item")
                                .icon(IconName::Close)
                                .label("Cancel")
                                .on_click(|_, window, cx| {
                                    window.dispatch_action(Box::new(CancelDialog), cx);
                                }),
                        )
                        .child(
                            button("confirm-delete-personal-item")
                                .danger()
                                .icon(Glyph::Trash)
                                .label("Delete")
                                .on_click(|_, window, cx| {
                                    window.dispatch_action(
                                        Box::new(ConfirmDialog { secondary: false }),
                                        cx,
                                    );
                                }),
                        ),
                )
                .on_ok(move |_, _, cx| {
                    let _ = view.update(cx, DesktopView::delete_personal_item);
                    true
                })
        });
    }

    fn delete_personal_item(&mut self, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Unsealed { .. }) || self.item_editor.is_some() {
            return;
        }
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        match self
            .runtime
            .delete_personal_secret(&item.id, self.personal_detail.version)
        {
            Ok(updated_contents) => {
                let item = self.personal_detail.item.take();
                self.apply_personal_contents(updated_contents);
                self.show_personal_panel(PersonalPanel::Overview, cx);
                if let Some(item) = item {
                    self.personal_history.record(Change::Delete {
                        item,
                        version: None,
                    });
                    self.show_toast("Item deleted", Some(Direction::Undo), false, cx);
                }
            }
            Err(PersonalWriteError::Changed(contents)) => self.show_changed_item(contents, cx),
            Err(PersonalWriteError::Failed(error)) => {
                self.personal_detail.error = Some(format!("Could not delete the item: {error}"));
                cx.notify();
            }
        }
    }

    pub(super) fn step_personal_history(&mut self, direction: Direction, cx: &mut Context<Self>) {
        if self.settings_open
            || !matches!(self.snapshot, Snapshot::Unsealed { .. })
            || self.item_editor.is_some()
        {
            return;
        }
        let Some(change) = self.personal_history.take(direction) else {
            return;
        };
        if let Change::Edit { item, .. } = &change
            && self
                .personal_detail
                .item
                .as_ref()
                .is_none_or(|open| open.id != item.id)
        {
            self.personal_history.clear();
            self.change_toast = None;
            cx.notify();
            return;
        }
        let result = match change.step(direction) {
            Step::Put(item) => self
                .runtime
                .put_personal_secret(item, change.version())
                .map(|(version, contents)| (Some(version), contents)),
            Step::Remove(id) => self
                .runtime
                .delete_personal_secret(id, change.version())
                .map(|contents| (None, contents)),
        };
        let (version, updated_contents) = match result {
            Ok(result) => result,
            Err(PersonalWriteError::Changed(contents)) => {
                self.show_changed_item(contents, cx);
                return;
            }
            Err(PersonalWriteError::Failed(error)) => {
                self.personal_history.keep(direction, change);
                let message = match direction {
                    Direction::Undo => format!("Could not undo: {error}"),
                    Direction::Redo => format!("Could not redo: {error}"),
                };
                self.show_toast(message, None, true, cx);
                return;
            }
        };
        self.apply_personal_contents(updated_contents);
        let message = match (direction, &change) {
            (Direction::Undo, _) => "Change undone",
            (Direction::Redo, Change::Edit { .. }) => "Saved",
            (Direction::Redo, Change::Delete { .. }) => "Item deleted",
        };
        match change {
            Change::Edit { item, .. } => {
                if let (Some(current), Some(version)) =
                    (self.personal_detail.item.replace(item), version)
                {
                    self.personal_history.applied(
                        direction,
                        Change::Edit {
                            item: current,
                            version,
                        },
                    );
                }
                self.personal_detail.version = version;
                self.reset_personal_inputs(cx);
            }
            Change::Delete { item, .. } => {
                let restored =
                    version.and_then(|version| Some((copied_item(&item).ok()?, version)));
                self.follow_restored_item(&item.id, direction, restored, cx);
                self.personal_history
                    .applied(direction, Change::Delete { item, version });
            }
        }
        self.show_toast(message, Some(direction.opposite()), false, cx);
        cx.notify();
    }

    fn follow_restored_item(
        &mut self,
        id: &str,
        direction: Direction,
        restored: Option<(PersonalSecret, ItemVersion)>,
        cx: &mut Context<Self>,
    ) {
        let open = matches!(&self.selected_vault_item, Some(VaultSelection::Entry(entry))
            if personal_item_id(entry) == Some(id));
        let entries = self
            .unsealed_contents()
            .map_or(&[][..], |contents| &contents.entries[..]);
        let target = match reopen_after(direction, id, open, entries) {
            Reopen::Item(entry) => Some(VaultSelection::Entry(Box::new(entry.clone()))),
            Reopen::List => Some(VaultSelection::PersonalSecrets),
            Reopen::Stay => None,
        };
        let history = std::mem::take(&mut self.personal_history);
        match target {
            Some(VaultSelection::PersonalSecrets) => {
                self.show_personal_panel(PersonalPanel::Overview, cx);
            }
            Some(VaultSelection::Entry(entry)) if let Some((item, version)) = restored => {
                self.open_saved_personal_item(*entry, item, version, cx);
            }
            Some(selection) => self.select_vault_item(selection, cx),
            None => {}
        }
        self.personal_history = history;
    }

    pub(super) fn show_toast(
        &mut self,
        message: impl Into<gpui::SharedString>,
        undo: Option<Direction>,
        error: bool,
        cx: &mut Context<Self>,
    ) {
        self.personal_toast = self.personal_toast.wrapping_add(1);
        let id = self.personal_toast;
        self.change_toast = Some(ChangeToast {
            id,
            message: message.into(),
            undo,
            error,
            leaving: false,
        });
        cx.spawn(async move |view, cx| {
            smol::Timer::after(PERSONAL_TOAST_LIFETIME).await;
            let _ = view.update(cx, |view, cx| view.dismiss_change_toast(id, cx));
        })
        .detach();
        cx.notify();
    }

    pub(super) fn copy_saved_personal_field(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(value) = self.saved_personal_value(index) else {
            return;
        };
        self.copy_personal_value(
            value.to_string(),
            personal_actions::CopiedField::Saved(index),
            cx,
        );
    }

    fn toggle_personal_favorite(&mut self, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Unsealed { .. }) || self.item_editor.is_some() {
            return;
        }
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        let result = favorite_item(item, !item.favorite)
            .map_err(PersonalWriteError::from)
            .and_then(|updated| self.save_personal_item(updated));
        match result {
            Ok(()) => {
                self.personal_detail.error = None;
                self.change_toast = None;
            }
            Err(PersonalWriteError::Changed(contents)) => self.show_changed_item(contents, cx),
            Err(PersonalWriteError::Failed(error)) => {
                self.personal_detail.error = Some(format!("Not saved: {error}"));
            }
        }
        cx.notify();
    }

    fn copy_personal_code(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(value) = self.saved_personal_value(index) else {
            return;
        };
        let Some(totp) = Totp::parse(&value) else {
            return;
        };
        let code = totp.code(unix_now()).to_string();
        self.copy_personal_value(code, personal_actions::CopiedField::Saved(index), cx);
    }

    fn toggle_personal_reveal(&mut self, index: usize, cx: &mut Context<Self>) {
        if !self.personal_detail.revealed.remove(&index) {
            self.personal_detail.revealed.insert(index);
        }
        let masked = !self.personal_detail.revealed.contains(&index);
        if let Some(input) = self.personal_detail.inputs.get(&index) {
            input.update(cx, |input, cx| input.set_masked(masked, cx));
        }
        cx.notify();
    }

    pub(super) fn render_personal_code(index: usize, totp: &Totp, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme();
        let now = unix_now();
        let remaining = totp.remaining(now);
        #[allow(clippy::cast_precision_loss)]
        let progress = remaining as f32 / totp.period() as f32 * 100.;
        h_flex()
            .h_8()
            .px_3()
            .gap_3()
            .items_center()
            .child(
                div()
                    .text_heading()
                    .font_semibold()
                    .font_family(theme.mono_font_family.clone())
                    .child(grouped(&totp.code(now))),
            )
            .child(
                ProgressCircle::new(("personal-code-countdown", index))
                    .with_size(Size::Large)
                    .color(if remaining <= 5 {
                        theme.danger
                    } else {
                        theme.muted_foreground
                    })
                    .value(progress),
            )
            .child(
                div()
                    .text_body()
                    .text_color(theme.muted_foreground)
                    .child(remaining.to_string()),
            )
    }

    pub(super) fn render_personal_strength(
        strength: crate::password_generator::Strength,
        cx: &mut Context<Self>,
    ) -> Div {
        div()
            .px_3()
            .max_w(rems(240. / 16.))
            .child(generator::strength_meter(strength, cx))
    }

    fn render_personal_value(
        &self,
        index: usize,
        label: &str,
        field: Option<&PersonalField>,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return div().into_any_element();
        };
        let value = self.saved_personal_value(index).unwrap_or_default();
        let field_type = field.map(|field| &field.field_type);
        let website = (field_type == Some(&PersonalFieldType::Url))
            .then(|| website_url(&value))
            .flatten();
        let totp = (field_type == Some(&PersonalFieldType::Totp))
            .then(|| Totp::parse(&value))
            .flatten();
        let code = totp
            .as_ref()
            .map(|totp| Self::render_personal_code(index, totp, cx));
        let show_input = code.is_none();
        let actions = PersonalActions {
            secret: field.is_none_or(PersonalField::is_concealed),
            empty: value.is_empty(),
            has_code: totp.is_some(),
            website,
        };
        let muted = cx.theme().muted_foreground;
        let icon = field.map_or_else(
            || IconName::File.into(),
            |field| personal_field_icon(&field.id, &field.field_type),
        );
        let group: gpui::SharedString = format!("personal-field-{index}").into();
        let edit_on_double_click =
            cx.listener(move |view, event: &gpui::MouseDownEvent, window, cx| {
                if event.click_count == 2 {
                    window.prevent_default();
                    cx.stop_propagation();
                    view.begin_edit(EditStart::Field(index), window, cx);
                }
            });
        item_editor::field_row(("personal-field", index), false, cx)
            .group(group.clone())
            .on_mouse_down(gpui::MouseButton::Left, edit_on_double_click)
            .child(item_editor::field_label(
                icon.size(rems(1.)).text_color(muted),
                div().min_w_0().truncate().child(label.to_owned()),
                muted,
            ))
            .child(
                item_editor::field_value()
                    .children(code)
                    .when(show_input, |value| value.child(input.clone())),
            )
            .child(self.render_personal_actions(index, actions, &group, cx))
            .into_any_element()
    }

    fn render_personal_more(cx: &mut Context<Self>) -> impl IntoElement {
        let view = cx.entity().downgrade();
        button("personal-item-more")
            .ghost()
            .icon(IconName::Ellipsis)
            .dropdown_menu(move |menu, _, _| {
                let view = view.clone();
                menu.item(PopupMenuItem::new("Delete").icon(Glyph::Trash).on_click(
                    move |_, window, cx| {
                        let _ = view.update(cx, |view, cx| {
                            view.confirm_delete_personal_item(window, cx);
                        });
                    },
                ))
            })
    }

    fn render_personal_actions(
        &self,
        index: usize,
        actions: PersonalActions,
        group: &gpui::SharedString,
        cx: &mut Context<Self>,
    ) -> Div {
        let copied =
            self.copied_personal_field == Some(personal_actions::CopiedField::Saved(index));
        let revealed = self.personal_detail.revealed.contains(&index);
        let shown = copied || revealed;
        let on_hover = |button: Button| {
            let button = button.transitions(|transitions| {
                controls::button_motion(transitions).opacity(crate::motion::hover())
            });
            if shown {
                button.opacity(1.)
            } else {
                button
                    .opacity(0.)
                    .group_hover(group.clone(), |style| style.opacity(1.))
                    .focus(|style| style.opacity(1.))
            }
        };
        let PersonalActions {
            secret,
            empty,
            has_code,
            website,
        } = actions;
        let labeled = |button: Button, label: &'static str| button.tooltip(label);
        item_editor::field_actions()
            .when(!empty, |row| {
                row.child(on_hover(
                    labeled(
                        button(("copy-personal-field", index))
                            .ghost()
                            .icon(if copied {
                                IconName::Check
                            } else {
                                IconName::Copy
                            }),
                        if copied { "Copied" } else { "Copy" },
                    )
                    .on_click(cx.listener(move |view, _, _, cx| {
                        if has_code {
                            view.copy_personal_code(index, cx);
                        } else {
                            view.copy_saved_personal_field(index, cx);
                        }
                    })),
                ))
            })
            .when_some(website, |row, url| {
                row.child(on_hover(
                    labeled(
                        button(("open-personal-link", index))
                            .ghost()
                            .icon(IconName::ExternalLink),
                        "Open",
                    )
                    .on_click(move |_, _, cx| cx.open_url(&url)),
                ))
            })
            .when(secret && !empty && !has_code, |row| {
                row.child(on_hover(
                    labeled(
                        button(("reveal-personal-field", index))
                            .ghost()
                            .icon(if revealed {
                                IconName::EyeOff
                            } else {
                                IconName::Eye
                            }),
                        if revealed { "Hide" } else { "Reveal" },
                    )
                    .on_click(cx.listener(move |view, _, _, cx| {
                        view.toggle_personal_reveal(index, cx);
                    })),
                ))
            })
    }
}

struct PersonalActions {
    secret: bool,
    empty: bool,
    has_code: bool,
    website: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn favoriting_preserves_everything_else() {
        let mut original = PersonalSecret::generic("Test".into(), "secret".into());
        original.tags.push("work".into());
        let favorite = favorite_item(&original, true).unwrap();
        let mut expected = serde_json::to_value(&original).unwrap();
        expected["favorite"] = true.into();
        assert_eq!(serde_json::to_value(&favorite).unwrap(), expected);
        assert_eq!(favorite_item(&favorite, false).unwrap(), original);
    }

    #[test]
    fn concealed_values_only_appear_after_reveal() {
        let mut field = PersonalField::new(
            "password",
            "Password",
            PersonalFieldType::Concealed,
            "secret value",
        );
        assert_eq!(field_text(&field, false), "••••••••");
        assert_eq!(field_text(&field, true), "secret value");
        field.concealed = false;
        assert_eq!(field_text(&field, false), "••••••••");
        let mut field =
            PersonalField::new("username", "Username", PersonalFieldType::Text, "alice");
        assert_eq!(field_text(&field, false), "alice");
        field.concealed = true;
        assert_eq!(field_text(&field, false), "••••••••");
    }

    #[test]
    fn clearing_details_discards_values_reveals_and_pending_reads() {
        let mut detail = PersonalDetail {
            item: Some(PersonalSecret::generic("Test".into(), "secret".into())),
            ..PersonalDetail::default()
        };
        detail.revealed.insert(0);
        assert!(detail.has_value(0));
        assert!(!detail.has_value(1));
        let generation = detail.generation;
        detail.clear();
        assert!(detail.item.is_none());
        assert!(detail.revealed.is_empty());
        assert!(!detail.has_value(0));
        assert_ne!(detail.generation, generation);
    }

    #[test]
    fn only_valid_one_time_codes_keep_the_countdown_running() {
        let mut item = PersonalSecret::template(PersonalSecretKind::Login, "Login".into());
        assert!(!has_one_time_code(&item));
        item.sections[0].fields[3].value = "otpauth://totp/Example".into();
        assert!(!has_one_time_code(&item));
        item.sections[0].fields[3].value = "JBSWY3DPEHPK3PXP".into();
        assert!(has_one_time_code(&item));
    }

    #[test]
    fn section_headings_skip_the_item_type_and_empty_sections() {
        let login = PersonalSecret::template(PersonalSecretKind::Login, "Login".into());
        assert!(!has_section_groups(&login));
        let mut identity = personal_templates::new_item_template(PersonalSecretKind::Identity);
        assert!(!has_section_groups(&identity));
        identity.sections[0].fields[0].value = "Alice".into();
        identity.sections[1].fields[1].value = "+380".into();
        assert!(has_section_groups(&identity));
        assert_eq!(
            section_heading(&identity, &identity.sections[0]),
            Some("Identification")
        );
        let card = personal_templates::new_item_template(PersonalSecretKind::Card);
        assert_eq!(section_heading(&card, &card.sections[0]), None);
        assert_eq!(
            section_heading(&card, &card.sections[1]),
            Some("Contact Information")
        );
    }

    #[test]
    fn rows_scroll_just_far_enough_to_show() {
        let viewport = Bounds::new(point(px(0.), px(100.)), size(px(500.), px(400.)));
        let row =
            |top: f32, height: f32| Bounds::new(point(px(0.), px(top)), size(px(500.), px(height)));
        assert_eq!(
            offset_showing(px(0.), px(600.), viewport, row(200., 80.)),
            px(0.)
        );
        assert_eq!(
            offset_showing(px(0.), px(600.), viewport, row(560., 80.)),
            px(-140.)
        );
        assert_eq!(
            offset_showing(px(-300.), px(600.), viewport, row(40., 80.)),
            px(-240.)
        );
        assert_eq!(
            offset_showing(px(0.), px(600.), viewport, row(600., 500.)),
            px(-500.)
        );
        assert_eq!(
            offset_showing(px(0.), px(100.), viewport, row(900., 80.)),
            px(-100.)
        );
    }

    #[test]
    fn undoing_a_delete_reopens_the_item_and_redoing_it_leaves() {
        let entry = factorseal::VaultEntryMetadata {
            access_project: None,
            display_name: Some("Hetzner Cloud".into()),
            display_type: Some("Login".into()),
            display_username: None,
            display_website: None,
            updated_at: None,
            favorite: false,
            document_kind: factorseal::DocumentKind::LocalKeyring,
            partition: PERSONAL_SECRET_NAMESPACE.to_vec(),
            address: factorseal::SecretAddress::new("hetzner".to_owned(), None).unwrap(),
        };
        let entries = [entry];
        assert_eq!(
            reopen_after(Direction::Undo, "hetzner", false, &entries),
            Reopen::Item(&entries[0])
        );
        assert_eq!(
            reopen_after(Direction::Undo, "other", true, &entries),
            Reopen::List
        );
        assert_eq!(
            reopen_after(Direction::Redo, "hetzner", true, &[]),
            Reopen::List
        );
        assert_eq!(
            reopen_after(Direction::Redo, "hetzner", false, &[]),
            Reopen::Stay
        );
    }

    #[test]
    fn websites_open_only_as_web_addresses() {
        assert_eq!(
            website_url(" https://github.com "),
            Some("https://github.com".into())
        );
        assert_eq!(
            website_url("http://router.local"),
            Some("http://router.local".into())
        );
        assert_eq!(website_url("github.com"), Some("https://github.com".into()));
        assert_eq!(website_url("javascript:alert(1)"), None);
        assert_eq!(website_url("file:///etc/passwd"), None);
        assert_eq!(website_url("not a site"), None);
        assert_eq!(website_url(""), None);
    }

    #[test]
    fn modified_dates_are_shown_in_the_given_time_zone() {
        let utc = jiff::tz::TimeZone::UTC;
        assert_eq!(
            modified_text(1_791_590_400, &utc).as_deref(),
            Some("Modified 10 October 2026")
        );
        assert_eq!(
            modified_text(1_791_590_399, &utc).as_deref(),
            Some("Modified 9 October 2026")
        );
        assert_eq!(modified_text(0, &utc), None);
        assert_eq!(modified_text(u64::MAX, &utc), None);
    }
}

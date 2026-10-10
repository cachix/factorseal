use std::collections::{HashMap, HashSet};

use gpui::{Pixels, ScrollHandle, canvas, point};
use gpui_component::progress::ProgressCircle;

use super::personal_history::{Change, Direction, Step};
use super::totp::{Totp, grouped, unix_now};
use super::*;

pub(super) struct ChangeToast {
    pub(super) id: u64,
    pub(super) message: gpui::SharedString,
    pub(super) undo: Option<Direction>,
    pub(super) error: bool,
}

#[derive(Default)]
pub(super) struct PersonalDetail {
    item: Option<PersonalSecret>,
    error: Option<String>,
    revealed: HashSet<usize>,
    added: HashSet<usize>,
    scrolling_to: Option<usize>,
    scroll: ScrollHandle,
    generation: u64,
    inputs: HashMap<usize, PersonalValueInput>,
    custom: Option<CustomFieldDraft>,
    subscriptions: Vec<Subscription>,
    ticker: Option<Task<()>>,
}

struct CustomFieldDraft {
    name: gpui::Entity<InputState>,
    field_type: PersonalFieldType,
    value: gpui::Entity<SecretInputState>,
    error: Option<String>,
    _subscriptions: [Subscription; 2],
}

struct PersonalValueInput {
    input: gpui::Entity<SecretInputState>,
    edited: bool,
    dirty: bool,
    error: Option<String>,
    strength: Option<crate::password_generator::Strength>,
    rating: Option<Task<()>>,
}

impl PersonalDetail {
    pub(super) fn item(&self) -> Option<&PersonalSecret> {
        self.item.as_ref()
    }

    pub(super) fn has_value(&self, index: usize, cx: &App) -> bool {
        self.inputs
            .get(&index)
            .is_some_and(|input| !input.input.read(cx).value().is_empty())
    }

    pub(super) fn has_pending_changes(&self) -> bool {
        self.inputs.values().any(|input| input.dirty)
    }

    pub(super) fn clear(&mut self) {
        self.subscriptions.clear();
        self.inputs.clear();
        self.custom = None;
        self.item = None;
        self.error = None;
        self.revealed.clear();
        self.added.clear();
        self.scrolling_to = None;
        self.scroll.set_offset(point(px(0.), px(0.)));
        self.ticker = None;
        self.generation = self.generation.wrapping_add(1);
    }
}

fn offset_showing(
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

fn field_is_secret(field: &PersonalField) -> bool {
    field.concealed || field.field_type.concealed()
}

fn field_text(field: &PersonalField, revealed: bool) -> String {
    if field_is_secret(field) && !revealed {
        "••••••••".into()
    } else {
        field.text().map_or_else(
            || serde_json::to_string_pretty(&field.value).unwrap_or_default(),
            ToOwned::to_owned,
        )
    }
}

fn field_is_empty(field: &PersonalField) -> bool {
    field.value.is_null() || field.text().is_some_and(str::is_empty)
}

#[derive(Clone, Debug, PartialEq)]
enum AddTarget {
    Existing(usize),
    Template(String),
}

#[derive(Clone, Debug, PartialEq)]
struct AddableField {
    label: String,
    id: String,
    field_type: PersonalFieldType,
    target: AddTarget,
}

fn template_fields(kind: PersonalSecretKind) -> Vec<(String, String, PersonalField)> {
    let mut template = personal_templates::new_item_template(kind);
    template
        .sections
        .iter_mut()
        .filter(|section| section.id != "notes")
        .flat_map(|section| {
            let (id, label) = (section.id.clone(), section.label.clone());
            std::mem::take(&mut section.fields)
                .into_iter()
                .map(move |field| (id.clone(), label.clone(), field))
        })
        .collect()
}

fn addable_fields(item: &PersonalSecret) -> Vec<AddableField> {
    let fields: Vec<_> = item
        .sections
        .iter()
        .flat_map(|section| &section.fields)
        .collect();
    let template = template_fields(item.kind);
    let rank = |id: &str| {
        template
            .iter()
            .position(|(_, _, field)| field.id == id)
            .unwrap_or(usize::MAX)
    };
    let mut addable: Vec<_> = fields
        .iter()
        .enumerate()
        .filter(|(_, field)| field_is_empty(field))
        .map(|(index, field)| AddableField {
            label: field.label.clone(),
            id: field.id.clone(),
            field_type: field.field_type.clone(),
            target: AddTarget::Existing(index),
        })
        .chain(
            template
                .iter()
                .filter(|(_, _, candidate)| !fields.iter().any(|field| field.id == candidate.id))
                .map(|(_, _, field)| AddableField {
                    label: field.label.clone(),
                    id: field.id.clone(),
                    field_type: field.field_type.clone(),
                    target: AddTarget::Template(field.id.clone()),
                }),
        )
        .collect();
    addable.sort_by_key(|field| rank(&field.id));
    addable.extend(
        item.notes
            .as_deref()
            .is_none_or(str::is_empty)
            .then(|| AddableField {
                label: "Notes".to_owned(),
                id: "notes".to_owned(),
                field_type: PersonalFieldType::Multiline,
                target: AddTarget::Existing(fields.len()),
            }),
    );
    addable
}

fn with_template_field(item: &PersonalSecret, id: &str) -> Result<(PersonalSecret, usize), String> {
    let template = template_fields(item.kind);
    let rank = |id: &str| template.iter().position(|(_, _, field)| field.id == id);
    let section_rank = |id: &str| template.iter().position(|(section, _, _)| section == id);
    let missing = || "This field is no longer available.".to_owned();
    let target = rank(id).ok_or_else(missing)?;
    let (section_id, section_label, field) = &template[target];
    let mut updated = copied_item(item)?;
    if updated
        .sections
        .iter()
        .flat_map(|section| &section.fields)
        .any(|existing| existing.id == field.id)
    {
        return Err(missing());
    }
    let section = if let Some(section) = updated
        .sections
        .iter()
        .position(|section| section.id == *section_id)
    {
        section
    } else {
        let after = section_rank(section_id);
        let at = updated
            .sections
            .iter()
            .position(|section| {
                section_rank(&section.id) > after || section_rank(&section.id).is_none()
            })
            .unwrap_or(updated.sections.len());
        updated.sections.insert(
            at,
            PersonalSection {
                id: section_id.clone(),
                label: section_label.clone(),
                fields: Vec::new(),
            },
        );
        at
    };
    let fields = &mut updated.sections[section].fields;
    let at = fields
        .iter()
        .position(|existing| rank(&existing.id).is_none_or(|existing| existing > target))
        .unwrap_or(fields.len());
    fields.insert(
        at,
        PersonalField::new(
            field.id.clone(),
            field.label.clone(),
            field.field_type.clone(),
            "",
        ),
    );
    let index = updated.sections[..section]
        .iter()
        .map(|section| section.fields.len())
        .sum::<usize>()
        + at;
    Ok((updated, index))
}

fn with_custom_field(
    item: &PersonalSecret,
    name: &str,
    field_type: PersonalFieldType,
    value: &str,
) -> Result<PersonalSecret, String> {
    let mut updated = copied_item(item)?;
    let count = updated
        .sections
        .iter()
        .map(|section| section.fields.len())
        .sum::<usize>();
    let id = (0..=count)
        .map(|number| format!("custom-{number}"))
        .find(|id| {
            !updated
                .sections
                .iter()
                .flat_map(|section| &section.fields)
                .any(|field| field.id == *id)
        })
        .unwrap_or_default();
    let name = match name.trim() {
        "" => "Custom field",
        name => name,
    };
    let field = PersonalField::new(id, name, field_type, value);
    match updated
        .sections
        .iter_mut()
        .find(|section| section.id == "custom")
    {
        Some(section) => section.fields.push(field),
        None => updated.sections.push(PersonalSection {
            id: "custom".into(),
            label: "Custom fields".into(),
            fields: vec![field],
        }),
    }
    Ok(updated)
}

fn has_section_groups(item: &PersonalSecret) -> bool {
    item.sections
        .iter()
        .filter(|section| !section.fields.is_empty())
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

const NAME_INDEX: usize = usize::MAX;
const ACTIONS_WIDTH: gpui::Rems = rems(19.);
const NARROW_ACTIONS_WIDTH: gpui::Rems = rems(7.);
const PERSONAL_TOAST_LIFETIME: std::time::Duration = std::time::Duration::from_secs(5);

fn copied_item(item: &PersonalSecret) -> Result<PersonalSecret, String> {
    let encoded = item.encode().map_err(|error| error.to_string())?;
    PersonalSecret::decode_current(&encoded).map_err(|error| error.to_string())
}

fn edited_item(item: &PersonalSecret, index: usize, value: &str) -> Result<PersonalSecret, String> {
    let mut updated = copied_item(item)?;
    if index == NAME_INDEX {
        if value.trim().is_empty() {
            return Err("Give this item a name.".into());
        }
        value.trim().clone_into(&mut updated.title);
    } else {
        let mut fields: Vec<_> = updated
            .sections
            .iter_mut()
            .flat_map(|section| &mut section.fields)
            .collect();
        if let Some(field) = fields.get_mut(index) {
            field.value = if field.value.is_string() {
                serde_json::Value::String(value.to_owned())
            } else {
                serde_json::from_str(value)
                    .map_err(|_| "Enter valid JSON for this structured field.".to_owned())?
            };
        } else if index == fields.len() {
            updated.notes = (!value.is_empty()).then(|| value.to_owned());
        } else {
            return Err("This field is no longer available.".into());
        }
    }
    Ok(updated)
}

fn custom_field(item: &PersonalSecret, index: usize) -> bool {
    item.sections
        .iter()
        .flat_map(|section| section.fields.iter().map(move |_| section.id.as_str()))
        .nth(index)
        == Some("custom")
}

fn without_field(item: &PersonalSecret, index: usize) -> Result<PersonalSecret, String> {
    let mut updated = copied_item(item)?;
    let mut remaining = index;
    for section in &mut updated.sections {
        if remaining < section.fields.len() {
            section.fields.remove(remaining);
            updated
                .sections
                .retain(|section| !section.fields.is_empty());
            return Ok(updated);
        }
        remaining -= section.fields.len();
    }
    Err("This field is no longer available.".into())
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
                if view.personal_detail.generation != generation
                    || !matches!(view.snapshot, Snapshot::Unsealed { .. })
                {
                    return;
                }
                match result {
                    Ok(item) => {
                        view.initialize_personal_inputs(&item, cx);
                        view.personal_detail.item = Some(item);
                        let indices: Vec<_> = view.personal_detail.inputs.keys().copied().collect();
                        for index in indices {
                            view.update_personal_strength(index, cx);
                        }
                        view.update_personal_ticker(cx);
                    }
                    Err(error) => view.personal_detail.error = Some(error),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn update_personal_ticker(&mut self, cx: &mut Context<Self>) {
        if !self
            .personal_detail
            .item
            .as_ref()
            .is_some_and(has_one_time_code)
        {
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

    #[allow(clippy::too_many_lines)]
    fn render_personal_item_content(
        &self,
        entry: &factorseal::VaultEntryMetadata,
        cx: &mut Context<Self>,
    ) -> Div {
        let theme = cx.theme().clone();
        let (title, kind) = vault_entry_label(entry);
        let mut panel = v_flex().w_full().gap_4().p_6().child(
            h_flex()
                .items_center()
                .gap_4()
                .child(personal_entry_icon(entry, 56. / 16., &theme))
                .child(
                    v_flex()
                        .min_w_0()
                        .gap_1()
                        .child(
                            h_flex()
                                .min_w_0()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .min_w_0()
                                        .text_title()
                                        .font_semibold()
                                        .truncate()
                                        .child(title),
                                )
                                .when_some(self.personal_detail.item.as_ref(), |row, item| {
                                    row.child(
                                        Button::new("toggle-personal-favorite")
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
                                }),
                        )
                        .child(
                            div()
                                .text_body()
                                .text_color(theme.muted_foreground)
                                .child(kind),
                        ),
                )
                .when(self.personal_detail.item.is_some(), |header| {
                    header.child(
                        Button::new("delete-personal-item")
                            .flex_none()
                            .ml_auto()
                            .icon(Glyph::Trash)
                            .label("Delete")
                            .on_click(cx.listener(|view, _, window, cx| {
                                view.confirm_delete_personal_item(window, cx);
                            })),
                    )
                }),
        );
        if let Some(error) = &self.personal_detail.error {
            panel = panel.child(error_banner(error.clone(), theme.danger));
        }
        let Some(item) = &self.personal_detail.item else {
            return panel.child(
                h_flex()
                    .gap_2()
                    .child(Spinner::new().small())
                    .child("Loading item…"),
            );
        };
        let hidden: Vec<_> = addable_fields(item)
            .into_iter()
            .filter(|field| match field.target {
                AddTarget::Existing(index) => !self.personal_field_visible(index),
                AddTarget::Template(_) => true,
            })
            .collect();
        let grouped = has_section_groups(item);
        let mut fields = v_flex().w_full().child(self.render_personal_value(
            NAME_INDEX,
            "Name",
            Glyph::Tag.into(),
            None,
            cx,
        ));
        let mut index = 0;
        for section in &item.sections {
            let mut rows = Vec::new();
            for field in &section.fields {
                if self.personal_field_visible(index) {
                    rows.push(self.render_personal_value(
                        index,
                        &field.label,
                        personal_field_icon(&field.id, &field.field_type),
                        Some(field),
                        cx,
                    ));
                }
                index += 1;
            }
            if let Some(heading) = section_heading(item, section).filter(|_| grouped)
                && !rows.is_empty()
            {
                fields = fields.child(
                    div()
                        .pt_5()
                        .pb_1()
                        .text_body()
                        .font_semibold()
                        .text_color(theme.muted_foreground)
                        .child(heading.to_owned()),
                );
            }
            fields = fields.children(rows);
        }
        if self.personal_field_visible(index) {
            fields = fields.child(self.render_personal_value(
                index,
                "Notes",
                IconName::File.into(),
                None,
                cx,
            ));
        }
        panel = panel
            .child(fields.children(self.render_custom_field_draft(cx)))
            .child(h_flex().child(Self::render_add_field(hidden, cx)));
        if let Some(modified) = entry
            .updated_at
            .and_then(|updated_at| modified_text(updated_at, &jiff::tz::TimeZone::system()))
        {
            panel = panel.child(
                div()
                    .text_body()
                    .text_color(theme.muted_foreground)
                    .child(modified),
            );
        }
        panel
    }

    fn personal_field_visible(&self, index: usize) -> bool {
        let Some(item) = &self.personal_detail.item else {
            return false;
        };
        let filled = item
            .sections
            .iter()
            .flat_map(|section| &section.fields)
            .nth(index)
            .map_or_else(
                || item.notes.as_deref().is_some_and(|notes| !notes.is_empty()),
                |field| !field_is_empty(field),
            );
        filled
            || self.personal_detail.added.contains(&index)
            || self
                .personal_detail
                .inputs
                .get(&index)
                .is_some_and(|input| input.edited)
    }

    fn render_add_field(
        hidden: Vec<AddableField>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let view = cx.entity().downgrade();
        Button::new("add-personal-field")
            .ghost()
            .icon(IconName::Plus)
            .label("Add field")
            .dropdown_menu(move |mut menu, _, _| {
                for field in &hidden {
                    let view = view.clone();
                    let target = field.target.clone();
                    menu = menu.item(
                        PopupMenuItem::new(field.label.clone())
                            .icon(personal_field_icon(&field.id, &field.field_type))
                            .on_click(move |_, window, cx| {
                                let _ = view.update(cx, |view, cx| {
                                    view.add_hidden_field(&target, window, cx);
                                });
                            }),
                    );
                }
                if !hidden.is_empty() {
                    menu = menu.separator();
                }
                let view = view.clone();
                menu.item(
                    PopupMenuItem::new("Custom field")
                        .icon(IconName::Plus)
                        .on_click(move |_, window, cx| {
                            let _ = view.update(cx, |view, cx| {
                                view.add_custom_field(window, cx);
                            });
                        }),
                )
            })
    }

    fn add_hidden_field(
        &mut self,
        target: &AddTarget,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match target {
            AddTarget::Existing(index) => self.add_personal_field(*index, window, cx),
            AddTarget::Template(id) => {
                if !self.flush_personal_changes(cx) {
                    return;
                }
                let Some(item) = &self.personal_detail.item else {
                    return;
                };
                match with_template_field(item, id) {
                    Ok((updated, index)) => {
                        self.personal_detail.item = Some(updated);
                        self.personal_detail.added = self
                            .personal_detail
                            .added
                            .iter()
                            .map(|added| if *added >= index { added + 1 } else { *added })
                            .collect();
                        self.reset_personal_inputs(cx);
                        self.add_personal_field(index, window, cx);
                    }
                    Err(error) => {
                        self.personal_detail.error = Some(format!("Not saved: {error}"));
                        cx.notify();
                    }
                }
            }
        }
    }

    fn add_custom_field(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.personal_detail.custom.is_none() {
            let name = cx.new(|cx| InputState::new(window, cx).default_value("Custom field"));
            let value = cx.new(|cx| {
                SecretInputState::from_value("", PersonalFieldType::Concealed.concealed(), cx)
                    .placeholder("Add a value")
            });
            let subscriptions = [
                cx.subscribe(&value, |view, _, event: &InputEvent, cx| {
                    if matches!(
                        event,
                        InputEvent::PressEnter {
                            secondary: false,
                            shift: false,
                        }
                    ) {
                        view.save_custom_field(cx);
                    }
                }),
                cx.subscribe(
                    &value,
                    |view, _, _: &crate::secret_input::CancelEdit, cx| {
                        view.cancel_custom_field(cx);
                    },
                ),
            ];
            self.personal_detail.custom = Some(CustomFieldDraft {
                name,
                field_type: PersonalFieldType::Concealed,
                value,
                error: None,
                _subscriptions: subscriptions,
            });
        }
        if let Some(draft) = &self.personal_detail.custom {
            draft.name.update(cx, |name, cx| {
                name.focus(window, cx);
                name.select_all(window, cx);
            });
        }
        cx.notify();
    }

    pub(super) fn cancel_custom_field(&mut self, cx: &mut Context<Self>) -> bool {
        let open = self.personal_detail.custom.take().is_some();
        if open {
            cx.notify();
        }
        open
    }

    fn save_custom_field(&mut self, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            return;
        }
        let Some(draft) = &self.personal_detail.custom else {
            return;
        };
        let value = draft.value.read(cx).value();
        if value.is_empty() {
            return;
        }
        let name = draft.name.read(cx).value();
        let field_type = draft.field_type.clone();
        if !self.flush_personal_changes(cx) {
            return;
        }
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        let result = with_custom_field(item, &name, field_type, &value).and_then(|updated| {
            self.runtime
                .put_personal_secret(&updated)
                .map(|contents| (updated, contents))
        });
        match result {
            Ok((updated, contents)) => {
                if let Some(previous) = self.personal_detail.item.take() {
                    self.personal_history.record(Change::Edit(previous));
                }
                self.apply_saved_personal_item(updated, contents);
                self.personal_detail.custom = None;
                self.personal_detail.error = None;
                self.reset_personal_inputs(cx);
                self.show_toast("Saved", Some(Direction::Undo), false, cx);
            }
            Err(error) => {
                if let Some(draft) = &mut self.personal_detail.custom {
                    draft.error = Some(format!("Not saved: {error}"));
                }
            }
        }
        cx.notify();
    }

    fn set_custom_field_kind(&mut self, kind: PersonalFieldType, cx: &mut Context<Self>) {
        if let Some(draft) = &mut self.personal_detail.custom {
            draft
                .value
                .update(cx, |value, cx| value.set_masked(kind.concealed(), cx));
            draft.field_type = kind;
            cx.notify();
        }
    }

    fn render_custom_field_draft(&self, cx: &mut Context<Self>) -> Option<Div> {
        let draft = self.personal_detail.custom.as_ref()?;
        let theme = cx.theme();
        let view = cx.entity().downgrade();
        let empty = draft.value.read(cx).value().is_empty();
        Some(
            v_flex()
                .w_full()
                .gap_2()
                .py_2()
                .border_b_1()
                .border_color(theme.border)
                .child(
                    h_flex()
                        .gap_2()
                        .child(div().flex_1().min_w_0().child(controls::hover_field(
                            "custom-field-name",
                            Input::new(&draft.name).bg(theming::input_background(cx)),
                        )))
                        .child(field_kind_picker(
                            "custom-field-kind",
                            &draft.field_type,
                            move |kind, cx| {
                                let _ = view.update(cx, |view, cx| {
                                    view.set_custom_field_kind(kind, cx);
                                });
                            },
                        )),
                )
                .child(draft.value.clone())
                .when_some(draft.error.clone(), |row, error| {
                    row.child(
                        div()
                            .px_3()
                            .text_caption()
                            .text_color(theme.danger)
                            .child(error),
                    )
                })
                .child(
                    h_flex()
                        .gap_2()
                        .child(
                            Button::new("save-custom-field")
                                .primary()
                                .small()
                                .icon(IconName::Check)
                                .label("Save")
                                .disabled(empty)
                                .on_click(cx.listener(|view, _, _, cx| {
                                    view.save_custom_field(cx);
                                })),
                        )
                        .child(
                            Button::new("cancel-custom-field")
                                .ghost()
                                .small()
                                .icon(IconName::Close)
                                .label("Cancel")
                                .on_click(cx.listener(|view, _, _, cx| {
                                    view.cancel_custom_field(cx);
                                })),
                        ),
                ),
        )
    }

    fn add_personal_field(&mut self, index: usize, window: &mut Window, cx: &mut Context<Self>) {
        self.personal_detail.added.insert(index);
        self.personal_detail.scrolling_to = Some(index);
        if let Some(input) = self.personal_detail.inputs.get(&index) {
            input.input.update(cx, |input, cx| input.focus(window, cx));
        }
        cx.notify();
    }

    fn scroll_to_personal_value(&self, cx: &mut Context<Self>) -> Div {
        let scroll = self.personal_detail.scroll.clone();
        let view = cx.entity().downgrade();
        div().absolute().inset_0().child(
            canvas(
                |_, _, _| {},
                move |bounds, (), window, cx| {
                    let offset = scroll.offset();
                    let target = offset_showing(
                        offset.y,
                        scroll.max_offset().y,
                        scroll.bounds(),
                        bounds.dilate(px(16.)),
                    );
                    if target != offset.y {
                        scroll.set_offset(point(offset.x, target));
                        window.refresh();
                    }
                    let _ = view.update(cx, |view, _| view.personal_detail.scrolling_to = None);
                },
            )
            .size_full(),
        )
    }

    fn initialize_personal_inputs(&mut self, item: &PersonalSecret, cx: &mut Context<Self>) {
        self.add_personal_input(NAME_INDEX, &item.title, false, false, cx);
        let mut index = 0;
        for field in item.sections.iter().flat_map(|section| &section.fields) {
            let value = Zeroizing::new(field_text(field, true));
            let wrapped = field.field_type == PersonalFieldType::Multiline;
            self.add_personal_input(index, &value, field_is_secret(field), wrapped, cx);
            index += 1;
        }
        self.add_personal_input(
            index,
            item.notes.as_deref().unwrap_or_default(),
            true,
            true,
            cx,
        );
    }

    fn add_personal_input(
        &mut self,
        index: usize,
        value: &str,
        masked: bool,
        wrapped: bool,
        cx: &mut Context<Self>,
    ) {
        let input = cx.new(|cx| {
            let input = SecretInputState::from_value(value, masked, cx)
                .plain()
                .placeholder("Add a value");
            if wrapped { input.wrapped() } else { input }
        });
        let subscription =
            cx.subscribe(&input, move |view, _, event: &InputEvent, cx| match event {
                InputEvent::Change => view.mark_personal_field_changed(index, cx),
                InputEvent::Blur
                | InputEvent::PressEnter {
                    secondary: false,
                    shift: false,
                } => view.save_personal_field(index, cx),
                _ => {}
            });
        self.personal_detail.subscriptions.push(subscription);
        self.personal_detail.subscriptions.push(cx.subscribe(
            &input,
            move |view, _, _: &crate::secret_input::CancelEdit, cx| {
                view.cancel_personal_field(index, cx);
            },
        ));
        self.personal_detail.inputs.insert(
            index,
            PersonalValueInput {
                input,
                edited: false,
                dirty: false,
                error: None,
                strength: None,
                rating: None,
            },
        );
    }

    fn rates_strength(&self, index: usize) -> bool {
        self.can_generate_saved_field(index)
            && self
                .personal_detail
                .item
                .as_ref()
                .is_some_and(|item| !custom_field(item, index))
    }

    fn update_personal_strength(&mut self, index: usize, cx: &mut Context<Self>) {
        let rated = self.rates_strength(index);
        let Some(input) = self.personal_detail.inputs.get_mut(&index) else {
            return;
        };
        let value = input.input.read(cx).value();
        input.strength =
            (rated && !value.is_empty()).then(|| crate::password_generator::Strength::of(&value));
    }

    fn mark_personal_field_changed(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(input) = self.personal_detail.inputs.get_mut(&index) else {
            return;
        };
        input.edited = true;
        input.dirty = true;
        input.error = None;
        self.copied_personal_field = None;
        if self.rates_strength(index) {
            self.rate_personal_field_later(index, cx);
        }
        cx.notify();
    }

    fn rate_personal_field_later(&mut self, index: usize, cx: &mut Context<Self>) {
        let rating = cx.spawn(async move |view, cx| {
            smol::Timer::after(crate::password_generator::RATING_PAUSE).await;
            let _ = view.update(cx, |view, cx| {
                view.update_personal_strength(index, cx);
                cx.notify();
            });
        });
        if let Some(input) = self.personal_detail.inputs.get_mut(&index) {
            input.rating = Some(rating);
        }
    }

    fn can_generate_saved_field(&self, index: usize) -> bool {
        self.personal_detail.item.as_ref().is_some_and(|item| {
            item.sections
                .iter()
                .flat_map(|section| &section.fields)
                .nth(index)
                .is_some_and(|field| {
                    personal_actions::can_generate_value(item.kind, &field.field_type, &field.id)
                })
        })
    }

    pub(super) fn use_generated_saved_value(
        &mut self,
        index: usize,
        password: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.can_generate_saved_field(index) {
            return;
        }
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return;
        };
        input.input.update(cx, |input, cx| {
            input.set_value(password, window, cx);
            input.focus(window, cx);
        });
        self.mark_personal_field_changed(index, cx);
    }

    pub(super) fn flush_personal_changes(&mut self, cx: &mut Context<Self>) -> bool {
        let dirty: Vec<_> = self
            .personal_detail
            .inputs
            .iter()
            .filter_map(|(index, input)| input.dirty.then_some(*index))
            .collect();
        for index in dirty {
            self.save_personal_field(index, cx);
        }
        !self.personal_detail.has_pending_changes()
    }

    fn saved_personal_value(&self, index: usize) -> Option<Zeroizing<String>> {
        let item = self.personal_detail.item.as_ref()?;
        if index == NAME_INDEX {
            return Some(Zeroizing::new(item.title.clone()));
        }
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

    fn cancel_personal_field(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(value) = self.saved_personal_value(index) else {
            return;
        };
        let Some(input) = self.personal_detail.inputs.get_mut(&index) else {
            return;
        };
        input
            .input
            .update(cx, |input, cx| input.replace(&value, cx));
        input.dirty = false;
        input.edited = false;
        input.error = None;
        if value.is_empty() {
            self.personal_detail.added.remove(&index);
        }
        self.update_personal_strength(index, cx);
        cx.notify();
    }

    fn save_personal_field(&mut self, index: usize, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            return;
        }
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return;
        };
        if !input.dirty {
            return;
        }
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        let edited = if input.input.read(cx).allocation_failed() {
            Err("Could not allocate secure memory. Re-enter the value.".into())
        } else {
            edited_item(item, index, &input.input.read(cx).value())
        };
        if edited.as_ref().is_ok_and(|updated| updated == item) {
            if let Some(input) = self.personal_detail.inputs.get_mut(&index) {
                input.dirty = false;
                input.error = None;
            }
            cx.notify();
            return;
        }
        let result = edited.and_then(|updated| {
            self.runtime
                .put_personal_secret(&updated)
                .map(|contents| (updated, contents))
        });
        match result {
            Ok((updated, updated_contents)) => {
                self.apply_personal_contents(updated_contents);
                if let Some(previous) = self.personal_detail.item.replace(updated) {
                    self.personal_history.record(Change::Edit(previous));
                    self.show_toast("Saved", Some(Direction::Undo), false, cx);
                }
                self.update_personal_ticker(cx);
                if let Some(input) = self.personal_detail.inputs.get_mut(&index) {
                    input.dirty = false;
                    input.error = None;
                }
                self.update_personal_strength(index, cx);
            }
            Err(error) => {
                if let Some(input) = self.personal_detail.inputs.get_mut(&index) {
                    input.error = Some(format!("Not saved: {error}"));
                }
            }
        }
        cx.notify();
    }

    fn apply_personal_contents(&mut self, updated_contents: VaultContents) {
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

    fn apply_saved_personal_item(
        &mut self,
        updated: PersonalSecret,
        updated_contents: VaultContents,
    ) {
        self.apply_personal_contents(updated_contents);
        self.personal_detail.item = Some(updated);
    }

    fn reset_personal_inputs(&mut self, cx: &mut Context<Self>) {
        self.personal_detail.subscriptions.clear();
        self.personal_detail.inputs.clear();
        self.personal_detail.revealed.clear();
        if let Some(item) = self.personal_detail.item.take() {
            self.initialize_personal_inputs(&item, cx);
            self.personal_detail.item = Some(item);
        }
        let indices: Vec<_> = self.personal_detail.inputs.keys().copied().collect();
        for index in indices {
            self.update_personal_strength(index, cx);
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
        window.open_dialog(cx, move |dialog, _, _| {
            let view = view.clone();
            dialog
                .title(title.clone())
                .width(px(420.))
                .child(div().text_body().child("You can undo this right after."))
                .footer(
                    DialogFooter::new()
                        .child(
                            Button::new("cancel-delete-personal-item")
                                .label("Cancel")
                                .on_click(|_, window, cx| {
                                    window.dispatch_action(Box::new(CancelDialog), cx);
                                }),
                        )
                        .child(
                            Button::new("confirm-delete-personal-item")
                                .danger()
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
        if !matches!(self.snapshot, Snapshot::Unsealed { .. }) || !self.flush_personal_changes(cx) {
            return;
        }
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        match self.runtime.delete_personal_secret(&item.id) {
            Ok(updated_contents) => {
                let item = self.personal_detail.item.take();
                self.apply_personal_contents(updated_contents);
                self.show_personal_panel(PersonalPanel::Overview, cx);
                if let Some(item) = item {
                    self.personal_history.record(Change::Delete(item));
                    self.show_toast("Item deleted", Some(Direction::Undo), false, cx);
                }
            }
            Err(error) => {
                self.personal_detail.error = Some(format!("Could not delete the item: {error}"));
                cx.notify();
            }
        }
    }

    pub(super) fn step_personal_history(&mut self, direction: Direction, cx: &mut Context<Self>) {
        if self.settings_open || !matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            return;
        }
        if self.personal_detail.has_pending_changes() {
            if direction == Direction::Undo {
                self.reset_personal_inputs(cx);
            }
            return;
        }
        let Some(change) = self.personal_history.take(direction) else {
            return;
        };
        if let Change::Edit(item) = &change
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
            Step::Put(item) => self.runtime.put_personal_secret(item),
            Step::Remove(id) => self.runtime.delete_personal_secret(id),
        };
        let updated_contents = match result {
            Ok(updated_contents) => updated_contents,
            Err(error) => {
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
            (Direction::Redo, Change::Edit(_)) => "Saved",
            (Direction::Redo, Change::Delete(_)) => "Item deleted",
        };
        match change {
            Change::Edit(item) => {
                if let Some(current) = self.personal_detail.item.replace(item) {
                    self.personal_history
                        .applied(direction, Change::Edit(current));
                }
                self.reset_personal_inputs(cx);
            }
            Change::Delete(item) => {
                self.follow_restored_item(&item.id, direction, cx);
                self.personal_history
                    .applied(direction, Change::Delete(item));
            }
        }
        self.show_toast(message, Some(direction.opposite()), false, cx);
        cx.notify();
    }

    fn follow_restored_item(&mut self, id: &str, direction: Direction, cx: &mut Context<Self>) {
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
        });
        cx.spawn(async move |view, cx| {
            smol::Timer::after(PERSONAL_TOAST_LIFETIME).await;
            let _ = view.update(cx, |view, cx| {
                if view
                    .change_toast
                    .as_ref()
                    .is_some_and(|toast| toast.id == id)
                {
                    view.change_toast = None;
                    cx.notify();
                }
            });
        })
        .detach();
        cx.notify();
    }

    pub(super) fn copy_saved_personal_field(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return;
        };
        let value = input.input.read(cx).value().to_string();
        self.copy_personal_value(value, personal_actions::CopiedField::Saved(index), cx);
    }

    fn remove_personal_field(&mut self, index: usize, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Unsealed { .. }) || !self.flush_personal_changes(cx) {
            return;
        }
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        let result = without_field(item, index).and_then(|updated| {
            self.runtime
                .put_personal_secret(&updated)
                .map(|contents| (updated, contents))
        });
        match result {
            Ok((updated, contents)) => {
                if let Some(previous) = self.personal_detail.item.take() {
                    self.personal_history.record(Change::Edit(previous));
                }
                self.apply_saved_personal_item(updated, contents);
                self.personal_detail.error = None;
                self.personal_detail.added.clear();
                self.reset_personal_inputs(cx);
                self.show_toast("Saved", Some(Direction::Undo), false, cx);
            }
            Err(error) => self.personal_detail.error = Some(format!("Not saved: {error}")),
        }
        cx.notify();
    }

    fn toggle_personal_favorite(&mut self, cx: &mut Context<Self>) {
        if !matches!(self.snapshot, Snapshot::Unsealed { .. }) {
            return;
        }
        let Some(item) = &self.personal_detail.item else {
            return;
        };
        let result = favorite_item(item, !item.favorite).and_then(|updated| {
            self.runtime
                .put_personal_secret(&updated)
                .map(|contents| (updated, contents))
        });
        match result {
            Ok((updated, contents)) => {
                if let Some(previous) = self.personal_detail.item.take() {
                    self.personal_history.record(Change::Edit(previous));
                }
                self.apply_saved_personal_item(updated, contents);
                self.personal_detail.error = None;
            }
            Err(error) => self.personal_detail.error = Some(format!("Not saved: {error}")),
        }
        cx.notify();
    }

    fn copy_personal_code(&mut self, index: usize, cx: &mut Context<Self>) {
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return;
        };
        let Some(totp) = Totp::parse(&input.input.read(cx).value()) else {
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
            input
                .input
                .update(cx, |input, cx| input.set_masked(masked, cx));
        }
        cx.notify();
    }

    fn render_personal_code(index: usize, totp: &Totp, cx: &mut Context<Self>) -> Div {
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
                    .font_family("monospace")
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

    fn render_personal_strength(
        strength: crate::password_generator::Strength,
        cx: &mut Context<Self>,
    ) -> Div {
        div()
            .px_3()
            .max_w(rems(240. / 16.))
            .child(generator::strength_meter(strength, cx))
    }

    #[allow(clippy::too_many_lines)]
    fn render_personal_value(
        &self,
        index: usize,
        label: &str,
        icon: gpui_component::Icon,
        field: Option<&PersonalField>,
        cx: &mut Context<Self>,
    ) -> Div {
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return div();
        };
        let field_type = field.map(|field| &field.field_type);
        let value = input.input.read(cx).value();
        let website = (field_type == Some(&PersonalFieldType::Url))
            .then(|| website_url(&value))
            .flatten();
        let totp = (field_type == Some(&PersonalFieldType::Totp))
            .then(|| Totp::parse(&value))
            .flatten();
        let code = totp
            .as_ref()
            .map(|totp| Self::render_personal_code(index, totp, cx));
        let strength = input
            .strength
            .map(|strength| Self::render_personal_strength(strength, cx));
        let scroll_to = (self.personal_detail.scrolling_to == Some(index))
            .then(|| self.scroll_to_personal_value(cx));
        let show_input = code.is_none() || self.personal_detail.revealed.contains(&index);
        let actions = PersonalActions {
            secret: field.map_or(index != NAME_INDEX, field_is_secret),
            empty: value.is_empty(),
            has_code: totp.is_some(),
            removable: self
                .personal_detail
                .item
                .as_ref()
                .is_some_and(|item| custom_field(item, index)),
            website,
        };
        let theme = cx.theme();
        let group: gpui::SharedString = format!("personal-field-{index}").into();
        h_flex()
            .group(group.clone())
            .relative()
            .w_full()
            .flex_wrap()
            .items_start()
            .gap_x_4()
            .py_1()
            .border_b_1()
            .border_color(theme.border)
            .children(scroll_to)
            .child(
                h_flex()
                    .w(rems(140. / 16.))
                    .flex_none()
                    .pt(rems(6. / 16.))
                    .gap_2()
                    .text_body()
                    .text_color(theme.muted_foreground)
                    .child(field_name_icon(icon, cx))
                    .child(div().min_w_0().child(label.to_owned())),
            )
            .child(
                h_flex()
                    .flex_grow(1.)
                    .flex_basis(rems(360. / 16.))
                    .min_w_0()
                    .items_start()
                    .gap_4()
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_1()
                            .children(code)
                            .when(show_input, |value| value.child(input.input.clone()))
                            .children(strength)
                            .when_some(input.error.clone(), |value, error| {
                                value.child(
                                    div()
                                        .px_3()
                                        .text_caption()
                                        .text_color(theme.danger)
                                        .child(error),
                                )
                            })
                            .when(input.dirty, |value| {
                                value.child(
                                    h_flex()
                                        .px_3()
                                        .py_1()
                                        .gap_2()
                                        .on_mouse_down(gpui::MouseButton::Left, |_, window, _| {
                                            window.prevent_default();
                                        })
                                        .child(
                                            Button::new(("save-personal-field", index))
                                                .primary()
                                                .small()
                                                .icon(IconName::Check)
                                                .label("Save")
                                                .on_click(cx.listener(move |view, _, _, cx| {
                                                    view.save_personal_field(index, cx);
                                                })),
                                        )
                                        .child(
                                            Button::new(("cancel-personal-field", index))
                                                .ghost()
                                                .small()
                                                .icon(IconName::Close)
                                                .label("Cancel")
                                                .on_click(cx.listener(
                                                    move |view, _, window, cx| {
                                                        view.cancel_personal_field(index, cx);
                                                        window.blur(cx);
                                                    },
                                                )),
                                        ),
                                )
                            }),
                    )
                    .child(self.render_personal_actions(index, actions, &group, cx)),
            )
    }

    #[allow(clippy::too_many_lines)]
    fn render_personal_actions(
        &self,
        index: usize,
        actions: PersonalActions,
        group: &gpui::SharedString,
        cx: &mut Context<Self>,
    ) -> Div {
        let Some(input) = self.personal_detail.inputs.get(&index) else {
            return div();
        };
        let copied =
            self.copied_personal_field == Some(personal_actions::CopiedField::Saved(index));
        let revealed = self.personal_detail.revealed.contains(&index);
        let generating = self.generator_target == Some(generator::GeneratorTarget::Saved(index));
        let shown = copied || revealed || generating || input.dirty || input.error.is_some();
        let on_hover = |button: Button| {
            if shown {
                button
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
            removable,
            website,
        } = actions;
        let icons_only = self.shortcuts.narrow;
        let labeled = |button: Button, label: &'static str| {
            if icons_only {
                button.tooltip(label)
            } else {
                button.label(label)
            }
        };
        h_flex()
            .flex_none()
            .min_w(if icons_only {
                NARROW_ACTIONS_WIDTH
            } else {
                ACTIONS_WIDTH
            })
            .justify_end()
            .gap_1()
            .when(!empty, |row| {
                row.child(on_hover(
                    labeled(
                        Button::new(("copy-personal-field", index))
                            .ghost()
                            .when(!icons_only, |button| {
                                button.w(personal_actions::COPY_BUTTON_WIDTH)
                            })
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
                        Button::new(("open-personal-link", index))
                            .ghost()
                            .icon(IconName::ExternalLink),
                        "Open",
                    )
                    .on_click(move |_, _, cx| cx.open_url(&url)),
                ))
            })
            .when(self.can_generate_saved_field(index), |row| {
                row.children(self.render_generator(
                    generator::GeneratorTarget::Saved(index),
                    icons_only,
                    |button| on_hover(button.ghost()),
                    cx,
                ))
            })
            .when(secret && !empty, |row| {
                row.child(on_hover(
                    labeled(
                        Button::new(("reveal-personal-field", index))
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
            .when(removable, |row| {
                row.child(on_hover(
                    Button::new(("remove-personal-field", index))
                        .ghost()
                        .icon(IconName::Delete)
                        .tooltip("Remove field")
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.remove_personal_field(index, cx);
                        })),
                ))
            })
    }
}

#[allow(clippy::struct_excessive_bools)]
struct PersonalActions {
    secret: bool,
    empty: bool,
    has_code: bool,
    removable: bool,
    website: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editing_preserves_identity_metadata_and_other_fields() {
        let mut original = PersonalSecret::generic("Test".into(), "secret".into());
        original.tags.push("work".into());
        original.favorite = true;
        original.source = Some(serde_json::json!({"imported": true}));
        original.sections[0].fields.push(PersonalField::new(
            "username",
            "Username",
            PersonalFieldType::Text,
            "alice",
        ));
        let updated = edited_item(&original, 0, "replacement").unwrap();
        let mut expected = serde_json::to_value(&original).unwrap();
        expected["sections"][0]["fields"][0]["value"] = "replacement".into();
        assert_eq!(serde_json::to_value(&updated).unwrap(), expected);
        assert_eq!(original.sections[0].fields[0].text(), Some("secret"));
        let renamed = edited_item(&updated, NAME_INDEX, " New name ").unwrap();
        assert_eq!(renamed.id, original.id);
        assert_eq!(renamed.title, "New name");
        assert!(edited_item(&updated, NAME_INDEX, "  ").is_err());
    }

    #[test]
    fn only_custom_fields_can_be_removed_and_removal_keeps_the_rest() {
        let mut item = PersonalSecret::generic("Test".into(), "secret".into());
        item.sections.push(PersonalSection {
            id: "custom".into(),
            label: "Custom fields".into(),
            fields: vec![
                PersonalField::new("custom-0", "PIN", PersonalFieldType::Concealed, "1"),
                PersonalField::new("custom-1", "Note", PersonalFieldType::Text, "2"),
            ],
        });
        assert!(!custom_field(&item, 0));
        assert!(custom_field(&item, 1));
        assert!(custom_field(&item, 2));
        assert!(!custom_field(&item, 3));
        let removed = without_field(&item, 1).unwrap();
        assert_eq!(removed.id, item.id);
        assert_eq!(removed.sections[1].fields.len(), 1);
        assert_eq!(removed.sections[1].fields[0].id, "custom-1");
        let emptied = without_field(&removed, 1).unwrap();
        assert_eq!(emptied.sections.len(), 1);
        assert!(without_field(&emptied, 5).is_err());
    }

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
    fn notes_and_structured_values_round_trip() {
        let mut original = PersonalSecret::generic("Test".into(), "secret".into());
        original.sections[0].fields[0].field_type = PersonalFieldType::Address;
        original.sections[0].fields[0].value = serde_json::json!({"street": "First"});
        assert!(edited_item(&original, 0, "invalid JSON").is_err());
        let updated = edited_item(&original, 0, r#"{"street":"Second"}"#).unwrap();
        assert_eq!(
            updated.sections[0].fields[0].value,
            serde_json::json!({"street": "Second"})
        );
        let updated = edited_item(&updated, 1, "Some notes").unwrap();
        assert_eq!(updated.notes.as_deref(), Some("Some notes"));
        assert!(edited_item(&updated, 1, "").unwrap().notes.is_none());
        assert!(edited_item(&updated, 2, "missing field").is_err());
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
        detail.added.insert(1);
        let generation = detail.generation;
        detail.clear();
        assert!(detail.item.is_none());
        assert!(detail.revealed.is_empty());
        assert!(detail.added.is_empty());
        assert_ne!(detail.generation, generation);
    }

    fn existing(
        index: usize,
        label: &str,
        id: &str,
        field_type: PersonalFieldType,
    ) -> AddableField {
        AddableField {
            label: label.to_owned(),
            id: id.to_owned(),
            field_type,
            target: AddTarget::Existing(index),
        }
    }

    #[test]
    fn empty_fields_and_notes_wait_behind_add_field() {
        let mut item = PersonalSecret::template(PersonalSecretKind::Login, "Login".into());
        item.sections[0].fields[0].value = "alice".into();
        assert_eq!(
            addable_fields(&item),
            vec![
                existing(1, "Password", "password", PersonalFieldType::Concealed),
                existing(2, "Website", "url-0", PersonalFieldType::Url),
                existing(3, "One-time password", "totp", PersonalFieldType::Totp),
                existing(4, "Notes", "notes", PersonalFieldType::Multiline),
            ]
        );
        item.notes = Some("Line one\nLine two".into());
        item.sections[0].fields[1].value = serde_json::json!({"structured": true});
        assert_eq!(
            addable_fields(&item),
            vec![
                existing(2, "Website", "url-0", PersonalFieldType::Url),
                existing(3, "One-time password", "totp", PersonalFieldType::Totp),
            ]
        );
    }

    #[test]
    fn missing_template_fields_can_be_added_in_template_order() {
        let mut item = PersonalSecret::new(PersonalSecretKind::Card, "Card".into());
        item.notes = Some("note".into());
        item.sections.push(PersonalSection {
            id: "card".into(),
            label: "Card".into(),
            fields: vec![PersonalField::new(
                "number",
                "Card number",
                PersonalFieldType::CardNumber,
                "4111",
            )],
        });
        item.sections.push(PersonalSection {
            id: "custom".into(),
            label: "Custom fields".into(),
            fields: vec![PersonalField::new(
                "custom-0",
                "PIN",
                PersonalFieldType::Concealed,
                "1",
            )],
        });
        let addable = addable_fields(&item);
        assert_eq!(
            addable
                .iter()
                .take(3)
                .map(|field| field.target.clone())
                .collect::<Vec<_>>(),
            [
                AddTarget::Template("cardholderName".into()),
                AddTarget::Template("type".into()),
                AddTarget::Template("code".into()),
            ]
        );
        assert!(addable.iter().all(|field| field.id != "number"));
        let (holder, index) = with_template_field(&item, "cardholderName").unwrap();
        assert_eq!(index, 0);
        assert_eq!(holder.sections[0].fields[0].id, "cardholderName");
        assert_eq!(holder.sections[0].fields[1].id, "number");
        assert_eq!(holder.id, item.id);
        let (bank, index) = with_template_field(&holder, "bank").unwrap();
        assert_eq!(
            bank.sections
                .iter()
                .map(|section| section.id.as_str())
                .collect::<Vec<_>>(),
            ["card", "contactInfo", "custom"]
        );
        assert_eq!(index, 2);
        assert!(with_template_field(&bank, "bank").is_err());
        assert!(with_template_field(&bank, "made-up").is_err());
    }

    #[test]
    fn custom_fields_join_the_custom_section_with_a_fresh_id() {
        let item = PersonalSecret::generic("Test".into(), "secret".into());
        let first = with_custom_field(&item, "  ", PersonalFieldType::Text, "a").unwrap();
        let custom = &first.sections[1];
        assert_eq!(custom.id, "custom");
        assert_eq!(custom.fields[0].id, "custom-0");
        assert_eq!(custom.fields[0].label, "Custom field");
        let second =
            with_custom_field(&first, "PIN", PersonalFieldType::Concealed, "1234").unwrap();
        assert_eq!(second.sections.len(), 2);
        let pin = &second.sections[1].fields[1];
        assert_eq!((pin.id.as_str(), pin.label.as_str()), ("custom-1", "PIN"));
        assert!(pin.concealed);
        assert_eq!(pin.text(), Some("1234"));
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
    fn section_headings_skip_the_item_type() {
        let login = PersonalSecret::template(PersonalSecretKind::Login, "Login".into());
        assert!(!has_section_groups(&login));
        let identity = personal_templates::new_item_template(PersonalSecretKind::Identity);
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
    fn added_fields_scroll_just_far_enough_to_show() {
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

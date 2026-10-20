use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use gpui::{Bounds, DragMoveEvent, Focusable as _, Pixels, SharedString, Task, canvas};
use gpui_component::{Icon, animation::ease_out_cubic, button::ButtonVariants, menu::PopupMenu};
use zeroize::Zeroize as _;

use super::generator::GeneratorTarget;
use super::personal_history::Direction;
use super::totp::{self, Totp, unix_now};
use super::*;
use crate::password_generator::Strength;
use crate::runtime::PersonalWriteError;
use crate::secret_input::{CancelEdit, PasteItem};

const NAME_MISSING: &str = "Give this item a name.";
const INVALID_JSON: &str = "Enter valid JSON for this structured field.";
const ALLOCATION_FAILED: &str = "Could not allocate secure memory. Re-enter the value.";
const NOTHING_ENTERED: &str = "Enter at least one field value.";
const VALUE_PLACEHOLDER: &str = "Add a value";
const ONE_TIME_PLACEHOLDER: &str = "Paste a setup key or QR code";
const USERNAME_ID: &str = "username";
const ONE_TIME_LABEL: &str = "One-time password";
const ONE_TIME_KEPT: &str = "This item already has this one-time password.";
const ONE_TIME_REPLACED: &str = "Saving replaces the current one-time password.";
const CUSTOM_SECTION: &str = "custom";
const CUSTOM_SECTION_LABEL: &str = "Custom fields";
const CUSTOM_LABEL: &str = "Custom field";
const WEBSITE_LABEL: &str = "Website";
const NOTES_ID: &str = "notes";
const NOTES_LABEL: &str = "Notes";
const TITLE_INSET: Pixels = px(13.);
const LABEL_WIDTH: gpui::Rems = rems(11.);
const LABEL_BLEED: Pixels = px(6.);
const VALUE_BASIS: gpui::Rems = rems(14.);
pub(super) const TITLE_BASIS: gpui::Rems = rems(10.);
const KIND_INSET: Pixels = px(6.);
const TITLE_LINE: gpui::Rems = rems(1.5 * std::f32::consts::GOLDEN_RATIO);
const TITLE_SPREAD: gpui::Rems = rems(5. / 16.);
const CHANGED_TINT: f32 = 0.08;
const SLIDE_DURATION: Duration = Duration::from_millis(180);
const GUARD_EVERY: Duration = Duration::from_secs(5);
const TOUCH_EVERY: Duration = Duration::from_secs(30);
const SAVE_MARGIN: u64 = 15;

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Addable {
    Template {
        id: String,
        label: String,
        field_type: PersonalFieldType,
    },
    Website,
    Custom(PersonalFieldType),
    Row {
        key: usize,
        id: String,
        label: String,
        field_type: PersonalFieldType,
    },
}

impl Addable {
    pub(super) fn label(&self) -> &str {
        match self {
            Self::Template { label, .. } | Self::Row { label, .. } => label,
            Self::Website => WEBSITE_LABEL,
            Self::Custom(field_type) => field_type.label(),
        }
    }

    pub(super) fn icon(&self) -> Icon {
        match self {
            Self::Row { id, .. } if id == NOTES_ID => IconName::File.into(),
            Self::Template { id, field_type, .. } | Self::Row { id, field_type, .. } => {
                personal_field_icon(id, field_type)
            }
            Self::Website => IconName::Globe.into(),
            Self::Custom(field_type) => personal_field_icon("", field_type),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Target {
    Name,
    Row(usize),
    Item,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct Problem {
    pub(super) target: Target,
    pub(super) message: String,
}

impl Problem {
    fn new(target: Target, message: impl Into<String>) -> Self {
        Self {
            target,
            message: message.into(),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct Seed<'a> {
    pub(super) index: Option<usize>,
    pub(super) value: &'a str,
    pub(super) label: &'a str,
    pub(super) concealed: bool,
    pub(super) custom: bool,
    pub(super) multiline: bool,
    pub(super) placeholder: &'static str,
}

pub(super) struct RowValue {
    pub(super) value: Zeroizing<String>,
    pub(super) label: Option<Zeroizing<String>>,
}

#[allow(clippy::struct_excessive_bools)]
pub(super) struct Row<V> {
    pub(super) key: usize,
    pub(super) id: String,
    pub(super) label: String,
    pub(super) field_type: PersonalFieldType,
    pub(super) concealed: bool,
    pub(super) custom: bool,
    pub(super) fresh: bool,
    pub(super) removed: bool,
    pub(super) hidden: bool,
    pub(super) inputs: V,
}

impl<V> Drop for Row<V> {
    fn drop(&mut self) {
        self.label.zeroize();
    }
}

pub(super) struct Section<V> {
    pub(super) id: String,
    pub(super) label: String,
    pub(super) rows: Vec<Row<V>>,
    stored_empty: bool,
}

impl<V> Drop for Section<V> {
    fn drop(&mut self) {
        self.label.zeroize();
    }
}

pub(super) struct Draft<V> {
    pub(super) kind: PersonalSecretKind,
    pub(super) sections: Vec<Section<V>>,
    pub(super) notes: Option<Row<V>>,
    next_key: usize,
}

struct TemplateField {
    section: String,
    section_label: String,
    id: String,
    label: String,
    field_type: PersonalFieldType,
    concealed: bool,
}

fn template_fields(kind: PersonalSecretKind) -> Vec<TemplateField> {
    let template = personal_templates::new_item_template(kind);
    template
        .sections
        .iter()
        .filter(|section| section.id != NOTES_ID)
        .flat_map(|section| {
            section.fields.iter().map(|field| TemplateField {
                section: section.id.clone(),
                section_label: section.label.clone(),
                id: field.id.clone(),
                label: field.label.clone(),
                field_type: field.field_type.clone(),
                concealed: field.concealed,
            })
        })
        .collect()
}

fn is_multiline(field_type: &PersonalFieldType) -> bool {
    matches!(
        field_type,
        PersonalFieldType::Multiline | PersonalFieldType::SshKey | PersonalFieldType::Address
    )
}

fn structured(value: &serde_json::Value) -> bool {
    !value.is_string() && !value.is_null()
}

fn value_text(value: &serde_json::Value) -> Zeroizing<String> {
    Zeroizing::new(match value {
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => String::new(),
        value => serde_json::to_string_pretty(value).unwrap_or_default(),
    })
}

fn stored_value(
    field_type: &PersonalFieldType,
    original: Option<&serde_json::Value>,
    entry: &str,
    salvage: bool,
) -> Result<serde_json::Value, String> {
    match original {
        Some(source) if structured(source) => {
            if *value_text(source) == *entry {
                Ok(source.clone())
            } else {
                match serde_json::from_str(entry) {
                    Ok(value) => Ok(value),
                    Err(_) if salvage => Ok(source.clone()),
                    Err(_) => Err(INVALID_JSON.to_owned()),
                }
            }
        }
        Some(serde_json::Value::Null) if entry.is_empty() => Ok(serde_json::Value::Null),
        _ if *field_type == PersonalFieldType::Totp
            && original.is_none_or(|source| *value_text(source) != *entry) =>
        {
            match totp::stored(entry) {
                Ok(stored) => Ok(serde_json::Value::String(stored.to_string())),
                Err(_) if salvage => Ok(serde_json::Value::String(entry.to_owned())),
                Err(error) => Err(error),
            }
        }
        _ => Ok(serde_json::Value::String(entry.to_owned())),
    }
}

fn one_time_value(item: &PersonalSecret) -> Option<&str> {
    item.sections
        .iter()
        .flat_map(|section| &section.fields)
        .find(|field| field.field_type == PersonalFieldType::Totp)
        .and_then(PersonalField::text)
}

fn find_field<'a>(item: &'a PersonalSecret, section: &str, id: &str) -> Option<&'a PersonalField> {
    item.sections
        .iter()
        .filter(|candidate| candidate.id == section)
        .flat_map(|section| &section.fields)
        .find(|field| field.id == id)
}

impl<V> Draft<V> {
    fn empty(kind: PersonalSecretKind) -> Self {
        Self {
            kind,
            sections: Vec::new(),
            notes: None,
            next_key: 0,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn new_row(
        &mut self,
        id: String,
        label: String,
        field_type: PersonalFieldType,
        concealed: bool,
        custom: bool,
        fresh: bool,
        inputs: V,
    ) -> Row<V> {
        let key = self.next_key;
        self.next_key += 1;
        Row {
            key,
            id,
            label,
            field_type,
            concealed,
            custom,
            fresh,
            removed: false,
            hidden: false,
            inputs,
        }
    }

    fn notes_row(
        &mut self,
        index: Option<usize>,
        value: &str,
        fresh: bool,
        make: &mut impl FnMut(Seed<'_>) -> V,
    ) -> Row<V> {
        let inputs = make(Seed {
            index,
            value,
            label: NOTES_LABEL,
            concealed: true,
            custom: false,
            multiline: true,
            placeholder: VALUE_PLACEHOLDER,
        });
        self.new_row(
            NOTES_ID.into(),
            NOTES_LABEL.into(),
            PersonalFieldType::Multiline,
            true,
            false,
            fresh,
            inputs,
        )
    }

    pub(super) fn from_item(item: &PersonalSecret, mut make: impl FnMut(Seed<'_>) -> V) -> Self {
        let mut draft = Self::empty(item.kind);
        let mut index = 0;
        for section in &item.sections {
            let custom = section.id == CUSTOM_SECTION;
            let mut rows = Vec::with_capacity(section.fields.len());
            for field in &section.fields {
                let value = value_text(&field.value);
                let inputs = make(Seed {
                    index: Some(index),
                    value: &value,
                    label: &field.label,
                    concealed: field.is_concealed(),
                    custom,
                    multiline: is_multiline(&field.field_type) || structured(&field.value),
                    placeholder: placeholder(&field.field_type),
                });
                let mut row = draft.new_row(
                    field.id.clone(),
                    field.label.clone(),
                    field.field_type.clone(),
                    field.concealed,
                    custom,
                    false,
                    inputs,
                );
                row.hidden = personal_detail::field_is_empty(field);
                rows.push(row);
                index += 1;
            }
            draft.sections.push(Section {
                id: section.id.clone(),
                label: section.label.clone(),
                rows,
                stored_empty: section.fields.is_empty(),
            });
        }
        let notes = item.notes.as_deref().unwrap_or_default();
        let mut notes_row = draft.notes_row(Some(index), notes, false, &mut make);
        notes_row.hidden = notes.is_empty();
        draft.notes = Some(notes_row);
        draft
    }

    pub(super) fn new_item(kind: PersonalSecretKind, mut make: impl FnMut(Seed<'_>) -> V) -> Self {
        Self::from_template(kind, &HashMap::new(), "", &mut make)
    }

    fn from_template(
        kind: PersonalSecretKind,
        values: &HashMap<String, Zeroizing<String>>,
        notes: &str,
        make: &mut impl FnMut(Seed<'_>) -> V,
    ) -> Self {
        let template = personal_templates::new_item_template(kind);
        let mut draft = Self::empty(kind);
        for section in template
            .sections
            .iter()
            .filter(|section| section.id != NOTES_ID)
        {
            let mut rows = Vec::with_capacity(section.fields.len());
            for field in &section.fields {
                let value = values.get(&field.id).map_or("", |value| value.as_str());
                let inputs = make(Seed {
                    index: None,
                    value,
                    label: &field.label,
                    concealed: field.is_concealed(),
                    custom: false,
                    multiline: is_multiline(&field.field_type),
                    placeholder: placeholder(&field.field_type),
                });
                rows.push(draft.new_row(
                    field.id.clone(),
                    field.label.clone(),
                    field.field_type.clone(),
                    field.concealed,
                    false,
                    true,
                    inputs,
                ));
            }
            draft.sections.push(Section {
                id: section.id.clone(),
                label: section.label.clone(),
                rows,
                stored_empty: false,
            });
        }
        draft.notes = Some(draft.notes_row(None, notes, true, make));
        draft
    }

    pub(super) fn field_rows(&self) -> impl Iterator<Item = &Row<V>> {
        self.sections.iter().flat_map(|section| &section.rows)
    }

    pub(super) fn rows(&self) -> impl Iterator<Item = &Row<V>> {
        self.field_rows().chain(&self.notes)
    }

    pub(super) fn row(&self, key: usize) -> Option<&Row<V>> {
        self.rows().find(|row| row.key == key)
    }

    fn row_mut(&mut self, key: usize) -> Option<&mut Row<V>> {
        self.sections
            .iter_mut()
            .flat_map(|section| &mut section.rows)
            .chain(&mut self.notes)
            .find(|row| row.key == key)
    }

    pub(super) fn key_at(&self, index: usize) -> Option<usize> {
        self.rows().nth(index).map(|row| row.key)
    }

    fn unused_id(&self, prefix: &str) -> String {
        (0..=self.field_rows().count())
            .map(|number| format!("{prefix}-{number}"))
            .find(|id| !self.field_rows().any(|row| row.id == *id))
            .unwrap_or_default()
    }

    fn website_slot(&self) -> Option<(usize, usize)> {
        if self.kind != PersonalSecretKind::Login {
            return None;
        }
        self.sections.iter().enumerate().find_map(|(at, section)| {
            section
                .rows
                .iter()
                .rposition(|row| {
                    !row.removed
                        && row.field_type == PersonalFieldType::Url
                        && row.id.starts_with("url")
                })
                .map(|row| (at, row))
        })
    }

    pub(super) fn addable(&self) -> Vec<Addable> {
        let hidden = |row: &Row<V>| {
            row.hidden.then(|| Addable::Row {
                key: row.key,
                id: row.id.clone(),
                label: if row.custom && row.label.trim().is_empty() {
                    CUSTOM_LABEL.to_owned()
                } else {
                    row.label.clone()
                },
                field_type: row.field_type.clone(),
            })
        };
        let present: HashSet<&str> = self.field_rows().map(|row| row.id.as_str()).collect();
        let missing = template_fields(self.kind)
            .into_iter()
            .filter(|field| !present.contains(field.id.as_str()))
            .map(|field| Addable::Template {
                id: field.id,
                label: field.label,
                field_type: field.field_type,
            });
        self.field_rows()
            .filter_map(hidden)
            .chain(missing)
            .chain(self.website_slot().map(|_| Addable::Website))
            .chain(self.notes.as_ref().and_then(hidden))
            .collect()
    }

    pub(super) fn insert_template(
        &mut self,
        id: &str,
        mut make: impl FnMut(Seed<'_>) -> V,
    ) -> Option<usize> {
        if self.field_rows().any(|row| row.id == id) {
            return None;
        }
        let template = template_fields(self.kind);
        let rank = |id: &str| template.iter().position(|field| field.id == id);
        let section_rank = |id: &str| template.iter().position(|field| field.section == id);
        let target = rank(id)?;
        let field = &template[target];
        let section = if let Some(section) = self
            .sections
            .iter()
            .position(|section| section.id == field.section)
        {
            section
        } else {
            let after = section_rank(&field.section);
            let at = self
                .sections
                .iter()
                .position(|section| {
                    section_rank(&section.id) > after || section_rank(&section.id).is_none()
                })
                .unwrap_or(self.sections.len());
            self.sections.insert(
                at,
                Section {
                    id: field.section.clone(),
                    label: field.section_label.clone(),
                    rows: Vec::new(),
                    stored_empty: false,
                },
            );
            at
        };
        let at = self.sections[section]
            .rows
            .iter()
            .position(|row| rank(&row.id).is_none_or(|existing| existing > target))
            .unwrap_or(self.sections[section].rows.len());
        let inputs = make(Seed {
            index: None,
            value: "",
            label: &field.label,
            concealed: field.concealed || field.field_type.concealed(),
            custom: false,
            multiline: is_multiline(&field.field_type),
            placeholder: placeholder(&field.field_type),
        });
        let row = self.new_row(
            field.id.clone(),
            field.label.clone(),
            field.field_type.clone(),
            field.concealed,
            false,
            true,
            inputs,
        );
        let key = row.key;
        self.sections[section].rows.insert(at, row);
        Some(key)
    }

    pub(super) fn insert_website(&mut self, mut make: impl FnMut(Seed<'_>) -> V) -> Option<usize> {
        let (section, after) = self.website_slot()?;
        let id = self.unused_id("url");
        let inputs = make(Seed {
            index: None,
            value: "",
            label: WEBSITE_LABEL,
            concealed: false,
            custom: false,
            multiline: false,
            placeholder: VALUE_PLACEHOLDER,
        });
        let row = self.new_row(
            id,
            WEBSITE_LABEL.into(),
            PersonalFieldType::Url,
            false,
            false,
            true,
            inputs,
        );
        let key = row.key;
        self.sections[section].rows.insert(after + 1, row);
        Some(key)
    }

    pub(super) fn insert_custom(
        &mut self,
        field_type: PersonalFieldType,
        mut make: impl FnMut(Seed<'_>) -> V,
    ) -> usize {
        self.push_custom("", field_type, "", &mut make)
    }

    fn push_custom(
        &mut self,
        label: &str,
        field_type: PersonalFieldType,
        value: &str,
        make: &mut impl FnMut(Seed<'_>) -> V,
    ) -> usize {
        let id = self.unused_id("custom");
        let concealed = field_type.concealed();
        let inputs = make(Seed {
            index: None,
            value,
            label,
            concealed,
            custom: true,
            multiline: is_multiline(&field_type),
            placeholder: placeholder(&field_type),
        });
        let row = self.new_row(
            id,
            label.to_owned(),
            field_type,
            concealed,
            true,
            true,
            inputs,
        );
        let key = row.key;
        let section = if let Some(section) = self
            .sections
            .iter()
            .position(|section| section.id == CUSTOM_SECTION)
        {
            section
        } else {
            self.sections.push(Section {
                id: CUSTOM_SECTION.into(),
                label: CUSTOM_SECTION_LABEL.into(),
                rows: Vec::new(),
                stored_empty: false,
            });
            self.sections.len() - 1
        };
        self.sections[section].rows.push(row);
        key
    }

    pub(super) fn remove(&mut self, key: usize, empty: bool) {
        for section in &mut self.sections {
            if let Some(at) = section.rows.iter().position(|row| row.key == key) {
                let row = &mut section.rows[at];
                if !empty {
                    row.removed = true;
                } else if row.fresh {
                    section.rows.remove(at);
                } else {
                    row.hidden = true;
                }
                return;
            }
        }
        if let Some(notes) = self.notes.as_mut().filter(|notes| notes.key == key) {
            if empty {
                notes.hidden = true;
            } else {
                notes.removed = true;
            }
        }
    }

    pub(super) fn show(&mut self, key: usize) -> bool {
        self.row_mut(key)
            .filter(|row| row.hidden)
            .map(|row| row.hidden = false)
            .is_some()
    }

    pub(super) fn restore(&mut self, key: usize) {
        if let Some(row) = self.row_mut(key) {
            row.removed = false;
        }
    }

    pub(super) fn section_keys(&self, key: usize) -> Vec<usize> {
        self.sections
            .iter()
            .find(|section| section.rows.iter().any(|row| row.key == key))
            .map(|section| {
                section
                    .rows
                    .iter()
                    .filter(|row| !row.hidden)
                    .map(|row| row.key)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub(super) fn move_row(&mut self, key: usize, target: usize) -> bool {
        for section in &mut self.sections {
            let from = section.rows.iter().position(|row| row.key == key);
            let to = section.rows.iter().position(|row| row.key == target);
            if let (Some(from), Some(to)) = (from, to) {
                if from == to {
                    return false;
                }
                let row = section.rows.remove(from);
                section.rows.insert(to, row);
                return true;
            }
        }
        false
    }

    pub(super) fn set_field_type(&mut self, key: usize, field_type: PersonalFieldType) -> bool {
        let Some(row) = self.row_mut(key).filter(|row| row.custom) else {
            return false;
        };
        row.concealed = field_type.concealed();
        row.field_type = field_type;
        true
    }

    pub(super) fn has_content(&self, values: &HashMap<usize, RowValue>) -> bool {
        self.rows().filter(|row| !row.removed).any(|row| {
            values
                .get(&row.key)
                .is_some_and(|value| !value.value.is_empty())
        })
    }

    pub(super) fn replaced(
        &self,
        base: &PersonalSecret,
        values: &HashMap<usize, RowValue>,
    ) -> HashSet<usize> {
        self.sections
            .iter()
            .flat_map(|section| {
                section.rows.iter().filter(move |row| {
                    let original =
                        (row.field_type == PersonalFieldType::Totp && !row.fresh && !row.removed)
                            .then(|| find_field(base, &section.id, &row.id))
                            .flatten()
                            .filter(|field| field.field_type == PersonalFieldType::Totp)
                            .and_then(PersonalField::text)
                            .filter(|original| !original.trim().is_empty());
                    original
                        .zip(values.get(&row.key))
                        .is_some_and(|(original, entry)| {
                            let value = entry.value.trim();
                            !value.is_empty()
                                && value != original.trim()
                                && !totp::same_key(original, value)
                        })
                })
            })
            .map(|row| row.key)
            .collect()
    }

    pub(super) fn changed(
        &self,
        base: &PersonalSecret,
        values: &HashMap<usize, RowValue>,
    ) -> HashSet<usize> {
        let kept = |row: &Row<V>, value: &str, label: &str| {
            values.get(&row.key).is_some_and(|entry| {
                *entry.value == *value
                    && entry
                        .label
                        .as_deref()
                        .is_none_or(|entry| entry.trim() == label.trim())
            })
        };
        let fields = self.sections.iter().flat_map(|section| {
            section.rows.iter().filter(move |row| {
                let original = (!row.fresh)
                    .then(|| find_field(base, &section.id, &row.id))
                    .flatten();
                !original.is_some_and(|field| {
                    field.field_type == row.field_type
                        && kept(row, &value_text(&field.value), &field.label)
                })
            })
        });
        let notes = self.notes.iter().filter(|notes| {
            !kept(
                notes,
                base.notes.as_deref().unwrap_or_default(),
                NOTES_LABEL,
            )
        });
        fields
            .chain(notes)
            .filter(|row| !row.removed)
            .map(|row| row.key)
            .collect()
    }

    pub(super) fn switched(
        &self,
        kind: PersonalSecretKind,
        values: &HashMap<usize, RowValue>,
        mut make: impl FnMut(Seed<'_>) -> V,
    ) -> Self {
        let template: HashSet<String> = template_fields(kind)
            .into_iter()
            .map(|field| field.id)
            .collect();
        let mut carried = HashMap::new();
        let mut extra = Vec::new();
        for row in self.field_rows().filter(|row| !row.removed) {
            let Some(entry) = values.get(&row.key).filter(|entry| !entry.value.is_empty()) else {
                continue;
            };
            if !row.custom && template.contains(&row.id) && !carried.contains_key(&row.id) {
                carried.insert(row.id.clone(), entry.value.clone());
            } else {
                let label = entry
                    .label
                    .as_deref()
                    .filter(|label| row.custom && !label.trim().is_empty())
                    .map_or_else(|| row.label.clone(), |label| label.trim().to_owned());
                extra.push((label, row.field_type.clone(), entry.value.clone()));
            }
        }
        let notes = self
            .notes
            .as_ref()
            .filter(|notes| !notes.removed)
            .and_then(|notes| values.get(&notes.key))
            .map_or_else(
                || Zeroizing::new(String::new()),
                |notes| notes.value.clone(),
            );
        let mut draft = Self::from_template(kind, &carried, notes.as_str(), &mut make);
        for (label, field_type, value) in extra {
            draft.push_custom(&label, field_type, &value, &mut make);
        }
        draft
    }

    pub(super) fn build(
        &self,
        base: Option<&PersonalSecret>,
        name: &str,
        read: impl Fn(&V) -> Option<RowValue>,
    ) -> Result<PersonalSecret, Problem> {
        self.assemble(base, name, read, false)
    }

    pub(super) fn salvage(
        &self,
        base: Option<&PersonalSecret>,
        name: &str,
        read: impl Fn(&V) -> Option<RowValue>,
    ) -> Result<PersonalSecret, Problem> {
        self.assemble(base, name, read, true)
    }

    fn assemble(
        &self,
        base: Option<&PersonalSecret>,
        name: &str,
        read: impl Fn(&V) -> Option<RowValue>,
        salvage: bool,
    ) -> Result<PersonalSecret, Problem> {
        let title = match name.trim() {
            "" if salvage => base.map_or(self.kind.label(), |base| base.title.trim()),
            "" => return Err(Problem::new(Target::Name, NAME_MISSING)),
            title => title,
        };
        let mut item = match base {
            Some(base) => personal_detail::copied_item(base)
                .map_err(|error| Problem::new(Target::Item, error))?,
            None => PersonalSecret::new(self.kind, String::new()),
        };
        if item.title.trim() != title {
            title.clone_into(&mut item.title);
        }
        let unreadable = |row: &Row<V>| Problem::new(Target::Row(row.key), ALLOCATION_FAILED);
        let mut filled = false;
        let mut sections = Vec::with_capacity(self.sections.len());
        for section in &self.sections {
            let mut fields = Vec::with_capacity(section.rows.len());
            for row in section.rows.iter().filter(|row| !row.removed) {
                let original = base
                    .filter(|_| !row.fresh)
                    .and_then(|base| find_field(base, &section.id, &row.id))
                    .map(|field| &field.value);
                let entry = match (read(&row.inputs), original) {
                    (Some(entry), _) => entry,
                    (None, Some(source)) if salvage => RowValue {
                        value: value_text(source),
                        label: None,
                    },
                    (None, None) if salvage => continue,
                    (None, _) => return Err(unreadable(row)),
                };
                filled |= !entry.value.is_empty();
                let value = stored_value(&row.field_type, original, &entry.value, salvage)
                    .map_err(|error| Problem::new(Target::Row(row.key), error))?;
                let label = match entry.label.as_deref().map(|label| label.trim()) {
                    Some(label) if row.custom && !label.is_empty() => label.to_owned(),
                    _ if row.custom && row.label.trim().is_empty() => CUSTOM_LABEL.to_owned(),
                    _ => row.label.clone(),
                };
                fields.push(PersonalField {
                    id: row.id.clone(),
                    label,
                    field_type: row.field_type.clone(),
                    concealed: row.concealed || row.field_type.concealed(),
                    value,
                });
            }
            if fields.is_empty() && !section.stored_empty {
                continue;
            }
            sections.push(PersonalSection {
                id: section.id.clone(),
                label: section.label.clone(),
                fields,
            });
        }
        item.sections = sections;
        let notes = match &self.notes {
            Some(row) if !row.removed => match read(&row.inputs) {
                Some(entry) => Some(entry.value),
                None if salvage => None,
                None => return Err(unreadable(row)),
            },
            _ => Some(Zeroizing::new(String::new())),
        };
        if let Some(notes) = notes {
            filled |= !notes.is_empty();
            if *notes != *item.notes.as_deref().unwrap_or_default() {
                item.notes = (!notes.is_empty()).then(|| notes.to_string());
            }
        }
        if base.is_none() && !filled {
            return Err(Problem::new(Target::Item, NOTHING_ENTERED));
        }
        Ok(item)
    }
}

fn shifts(before: &[usize], after: &[usize], heights: &HashMap<usize, f32>) -> Vec<(usize, f32)> {
    if before.iter().any(|key| !heights.contains_key(key)) {
        return Vec::new();
    }
    let tops = |order: &[usize]| -> HashMap<usize, f32> {
        order
            .iter()
            .scan(0., |top, key| {
                let at = *top;
                *top += heights[key];
                Some((*key, at))
            })
            .collect()
    };
    let (old, new) = (tops(before), tops(after));
    after
        .iter()
        .map(|key| (*key, old[key] - new[key]))
        .filter(|(_, shift)| shift.abs() > f32::EPSILON)
        .collect()
}

#[derive(Debug, PartialEq)]
enum Guard {
    Wait,
    Touch,
    Save,
}

fn guard(
    now: u64,
    (idle, absolute): (u64, u64),
    active: bool,
    since_touch: Duration,
    changed: bool,
) -> Guard {
    let near = |deadline: u64| deadline.saturating_sub(now) <= SAVE_MARGIN;
    if changed && near(absolute) {
        Guard::Save
    } else if active && (since_touch >= TOUCH_EVERY || near(idle)) {
        Guard::Touch
    } else if changed && near(idle) {
        Guard::Save
    } else {
        Guard::Wait
    }
}

#[derive(Clone, Copy)]
struct Slide {
    from: f32,
    started: Instant,
}

impl Slide {
    fn offset(self, now: Instant) -> f32 {
        let progress =
            now.duration_since(self.started).as_secs_f32() / SLIDE_DURATION.as_secs_f32();
        if progress >= 1. {
            0.
        } else {
            self.from * (1. - ease_out_cubic(progress))
        }
    }
}

pub(super) struct Inputs {
    pub(super) value: gpui::Entity<SecretInputState>,
    pub(super) label: Option<gpui::Entity<InputState>>,
}

pub(super) struct Editor {
    item_id: Option<String>,
    draft: Draft<Inputs>,
    problems: Vec<Problem>,
    notices: HashMap<usize, &'static str>,
    origin_pending: bool,
    strengths: HashMap<usize, Strength>,
    ratings: HashMap<usize, Task<()>>,
    scroll_to: Option<usize>,
    subscriptions: Vec<Subscription>,
    dragging: Option<usize>,
    slides: HashMap<usize, Slide>,
    slots: Rc<RefCell<HashMap<usize, Bounds<Pixels>>>>,
    active: bool,
    touched: Instant,
    guard: Option<Task<()>>,
    arrived: HashSet<usize>,
    focused_value: Option<usize>,
    focused_name: Option<usize>,
    title_focused: bool,
}

impl Editor {
    fn new(item_id: Option<String>, draft: Draft<Inputs>) -> Self {
        Self {
            item_id,
            draft,
            problems: Vec::new(),
            notices: HashMap::new(),
            origin_pending: false,
            strengths: HashMap::new(),
            ratings: HashMap::new(),
            scroll_to: None,
            subscriptions: Vec::new(),
            dragging: None,
            slides: HashMap::new(),
            slots: Rc::default(),
            active: false,
            touched: Instant::now(),
            guard: None,
            arrived: HashSet::new(),
            focused_value: None,
            focused_name: None,
            title_focused: false,
        }
    }

    fn slide(&mut self, before: &[usize], after: &[usize]) {
        let heights: HashMap<usize, f32> = {
            let slots = self.slots.borrow();
            before
                .iter()
                .filter_map(|key| {
                    slots
                        .get(key)
                        .map(|slot| (*key, f32::from(slot.size.height)))
                })
                .collect()
        };
        let now = Instant::now();
        for (key, shift) in shifts(before, after, &heights) {
            let current = self.slides.get(&key).map_or(0., |slide| slide.offset(now));
            self.slides.insert(
                key,
                Slide {
                    from: shift + current,
                    started: now,
                },
            );
        }
    }

    fn offset(&self, key: usize, now: Instant) -> f32 {
        self.slides.get(&key).map_or(0., |slide| slide.offset(now))
    }

    pub(super) fn is_new(&self) -> bool {
        self.item_id.is_none()
    }

    fn problem(&self, target: Target) -> Option<&str> {
        self.problems
            .iter()
            .find(|problem| problem.target == target)
            .map(|problem| problem.message.as_str())
    }
}

#[derive(PartialEq, Eq)]
pub(super) enum QrTarget {
    Vault,
    NewItem,
    Item(String),
}

#[derive(Clone, Copy)]
struct Marks {
    changed: bool,
    replaced: bool,
}

type LeaveRequest = Box<dyn FnOnce(&mut DesktopView, &mut Context<DesktopView>)>;

#[derive(Default)]
pub(super) struct Leave {
    request: Option<LeaveRequest>,
    dialog: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum EditStart {
    Top,
    Field(usize),
    Add(Addable),
}

#[derive(Clone)]
struct DraggedRow {
    key: usize,
    label: SharedString,
    size: Option<gpui::Size<Pixels>>,
}

impl Render for DraggedRow {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme();
        h_flex()
            .when_some(self.size, |row, size| row.w(size.width).h(size.height))
            .items_start()
            .px_2()
            .py_1()
            .rounded(theme.radius)
            .border_1()
            .border_color(theme.border)
            .bg(theme.popover)
            .shadow_lg()
            .child(field_label(
                Icon::from(Glyph::Grip).small(),
                self.label.clone(),
                theme.popover_foreground,
            ))
    }
}

pub(super) fn field_group(
    heading: Option<SharedString>,
    rows: impl IntoIterator<Item = gpui::AnyElement>,
    cx: &App,
) -> Div {
    v_flex()
        .w_full()
        .when_some(heading, |group, heading| {
            group.child(
                div()
                    .pb_1()
                    .text_body()
                    .font_semibold()
                    .text_color(cx.theme().muted_foreground)
                    .child(heading),
            )
        })
        .children(rows)
}

pub(super) fn field_row(
    id: impl Into<gpui::ElementId>,
    editing: bool,
    cx: &App,
) -> gpui::Stateful<Div> {
    let border = cx.theme().border;
    h_flex()
        .id(id)
        .relative()
        .w_full()
        .flex_wrap()
        .items_start()
        .gap_x_3()
        .py_1()
        .border_b_1()
        .border_color(if editing { border.opacity(0.) } else { border })
}

pub(super) fn field_label(icon: impl IntoElement, label: impl IntoElement, color: Hsla) -> Div {
    h_flex()
        .w(LABEL_WIDTH)
        .flex_none()
        .h_8()
        .items_center()
        .gap_2()
        .text_body()
        .text_color(color)
        .child(
            div()
                .relative()
                .flex_none()
                .size_4()
                .flex()
                .items_center()
                .justify_center()
                .child(icon),
        )
        .child(
            div()
                .relative()
                .flex_1()
                .min_w_0()
                .h_full()
                .flex()
                .items_center()
                .child(label),
        )
}

pub(super) fn field_body() -> Div {
    h_flex()
        .flex_grow(1.)
        .flex_basis(VALUE_BASIS)
        .min_w_0()
        .items_start()
        .gap_3()
}

pub(super) fn field_value() -> Div {
    v_flex().flex_1().min_w_0().gap_1()
}

pub(super) fn field_actions() -> Div {
    h_flex().flex_none().h_8().items_center().gap_0p5()
}

fn action_slot() -> Div {
    div().flex_none().size_8()
}

pub(super) fn shown_on_hover(
    id: impl Into<gpui::ElementId>,
    group: SharedString,
    shown: bool,
    element: Div,
) -> gpui::Stateful<Div> {
    element
        .id(id)
        .transitions(|transitions| transitions.opacity(crate::motion::hover()))
        .opacity(if shown { 1. } else { 0. })
        .when(!shown, |element| {
            element.group_hover(group, |style| style.opacity(1.))
        })
}

fn hidden_on_hover(
    id: impl Into<gpui::ElementId>,
    group: SharedString,
    element: Div,
) -> gpui::Stateful<Div> {
    element
        .id(id)
        .transitions(|transitions| transitions.opacity(crate::motion::hover()))
        .opacity(1.)
        .group_hover(group, |style| style.opacity(0.))
}

fn value_fill(
    name: &str,
    group: SharedString,
    focused: bool,
    changed: bool,
    bleed: Pixels,
    cx: &App,
) -> impl IntoElement {
    let theme = cx.theme();
    let hover = theme.muted_foreground.opacity(0.4);
    crate::motion::fade(
        SharedString::from(format!("{name}-fill")),
        div()
            .id(SharedString::from(format!("{name}-frame")))
            .absolute()
            .top_0()
            .bottom_0()
            .right_0()
            .left(-bleed)
            .rounded(theme.radius)
            .border_1()
            .bg(theming::input_background(cx))
            .transitions(|transitions| transitions.border_color(crate::motion::hover()))
            .border_color(if focused {
                theme.muted_foreground
            } else {
                theme.input.opacity(0.)
            })
            .when(!focused, |fill| {
                fill.group_hover(group, move |style| style.border_color(hover))
            })
            .child(
                div()
                    .id(SharedString::from(format!("{name}-tint")))
                    .size_full()
                    .rounded(theme.radius)
                    .transitions(|transitions| transitions.bg(crate::motion::change()))
                    .bg(theme
                        .warning
                        .opacity(if changed { CHANGED_TINT } else { 0. })),
            ),
    )
}

fn placeholder(field_type: &PersonalFieldType) -> &'static str {
    if *field_type == PersonalFieldType::Totp {
        ONE_TIME_PLACEHOLDER
    } else {
        VALUE_PLACEHOLDER
    }
}

fn make_value(
    value: &str,
    masked: bool,
    multiline: bool,
    placeholder: &'static str,
    cx: &mut Context<DesktopView>,
) -> gpui::Entity<SecretInputState> {
    cx.new(|cx| {
        let input = SecretInputState::from_value(value, masked, cx)
            .bare()
            .placeholder(placeholder);
        if multiline {
            input.wrapped().newline_on_enter()
        } else {
            input
        }
    })
}

fn with_custom_fields(
    menu: PopupMenu,
    window: &mut Window,
    cx: &mut Context<PopupMenu>,
    pick: impl Fn(PersonalFieldType, &mut Window, &mut App) + 'static,
) -> PopupMenu {
    let pick = Rc::new(pick);
    menu.separator().submenu_with_icon(
        Some(IconName::Plus.into()),
        CUSTOM_LABEL,
        window,
        cx,
        move |mut menu, _, _| {
            for field_type in CUSTOM_FIELD_KINDS {
                let pick = Rc::clone(&pick);
                menu = menu.item(
                    PopupMenuItem::new(field_type.label())
                        .icon(personal_field_icon("", &field_type))
                        .on_click(move |_, window, cx| pick(field_type.clone(), window, cx)),
                );
            }
            menu
        },
    )
}

fn one_time_row<V>(draft: &Draft<V>, preferred: Option<usize>) -> Option<&Row<V>> {
    let shown = || {
        draft
            .field_rows()
            .filter(|row| row.field_type == PersonalFieldType::Totp && !row.removed && !row.hidden)
    };
    shown()
        .find(|row| Some(row.key) == preferred)
        .or_else(|| shown().next())
}

fn make_inputs(
    seed: Seed<'_>,
    revealed: &HashSet<usize>,
    window: &mut Window,
    cx: &mut Context<DesktopView>,
) -> Inputs {
    let masked = seed.concealed && !seed.index.is_some_and(|index| revealed.contains(&index));
    let value = make_value(seed.value, masked, seed.multiline, seed.placeholder, cx);
    let label = seed.custom.then(|| {
        let label = seed.label.to_owned();
        cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Field name")
                .default_value(label)
        })
    });
    Inputs { value, label }
}

fn read_inputs(inputs: &Inputs, cx: &App) -> Option<RowValue> {
    let value = inputs.value.read(cx);
    (!value.allocation_failed()).then(|| RowValue {
        value: value.value(),
        label: inputs
            .label
            .as_ref()
            .map(|label| Zeroizing::new(label.read(cx).value().to_string())),
    })
}

fn watch_row(key: usize, inputs: &Inputs, cx: &mut Context<DesktopView>) -> Vec<Subscription> {
    let mut subscriptions = vec![
        cx.subscribe(
            &inputs.value,
            move |view, _, event: &InputEvent, cx| match event {
                InputEvent::Change => view.editor_value_changed(key, cx),
                InputEvent::PressEnter {
                    secondary: false,
                    shift: false,
                } => {
                    view.save_item_editor(cx);
                }
                _ => {}
            },
        ),
        cx.subscribe(&inputs.value, |view, _, _: &CancelEdit, cx| {
            view.cancel_item_editor(cx);
        }),
        cx.subscribe(
            &inputs.value,
            move |view, _, PasteItem(item): &PasteItem, cx| {
                view.paste_into_row(item, key, cx);
            },
        ),
    ];
    if let Some(label) = &inputs.label {
        subscriptions.push(cx.subscribe(
            label,
            move |view, _, event: &InputEvent, cx| match event {
                InputEvent::Change => view.editor_value_changed(key, cx),
                InputEvent::PressEnter { .. } => {
                    view.save_item_editor(cx);
                }
                _ => {}
            },
        ));
    }
    subscriptions
}

impl DesktopView {
    pub(super) fn editing_item(&self) -> bool {
        self.item_editor
            .as_ref()
            .is_some_and(|editor| !editor.is_new())
    }

    pub(super) fn begin_edit(
        &mut self,
        start: EditStart,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.is_unsealed() {
            return;
        }
        if !self.editing_item() {
            let Some(item) = self.personal_detail.item() else {
                return;
            };
            let revealed = self.personal_detail.revealed().clone();
            let title = item.title.clone();
            let id = item.id.clone();
            let draft = Draft::from_item(item, |seed| make_inputs(seed, &revealed, window, cx));
            self.close_generator(cx);
            self.item_name
                .update(cx, |name, cx| name.set_value(title, window, cx));
            self.item_editor = Some(Editor::new(Some(id), draft));
            self.watch_item_editor(cx);
            self.guard_item_editor(cx);
        }
        let key = match start {
            EditStart::Top => None,
            EditStart::Field(index) => self
                .item_editor
                .as_ref()
                .and_then(|editor| editor.draft.key_at(index)),
            EditStart::Add(addable) => {
                self.editor_add(addable, window, cx);
                return;
            }
        };
        self.focus_editor_row(key, window, cx);
    }

    pub(super) fn ensure_new_item_editor(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let drafting = self.is_unsealed()
            && self.selected_vault_item == Some(VaultSelection::PersonalSecrets)
            && self.personal_panel == PersonalPanel::NewItem;
        if !drafting || self.item_editor.as_ref().is_some_and(Editor::is_new) {
            return;
        }
        let revealed = HashSet::new();
        let draft = Draft::new_item(PersonalSecretKind::Login, |seed| {
            make_inputs(seed, &revealed, window, cx)
        });
        self.item_name.update(cx, |name, cx| {
            name.set_value("", window, cx);
            name.focus(window, cx);
        });
        self.item_editor = Some(Editor::new(None, draft));
        self.watch_item_editor(cx);
        self.guard_item_editor(cx);
    }

    fn watch_item_editor(&mut self, cx: &mut Context<Self>) {
        let Some(editor) = &self.item_editor else {
            return;
        };
        let rows: Vec<_> = editor
            .draft
            .rows()
            .map(|row| {
                (
                    row.key,
                    Inputs {
                        value: row.inputs.value.clone(),
                        label: row.inputs.label.clone(),
                    },
                )
            })
            .collect();
        let mut subscriptions = vec![cx.subscribe(
            &self.item_name,
            |view, _, event: &InputEvent, cx| match event {
                InputEvent::Change => {
                    if let Some(editor) = &mut view.item_editor {
                        editor
                            .problems
                            .retain(|problem| problem.target != Target::Name);
                    }
                    cx.notify();
                }
                InputEvent::PressEnter { .. } => {
                    view.save_item_editor(cx);
                }
                _ => {}
            },
        )];
        for (key, inputs) in &rows {
            subscriptions.extend(watch_row(*key, inputs, cx));
        }
        if let Some(editor) = &mut self.item_editor {
            editor.subscriptions = subscriptions;
        }
    }

    fn focus_editor_row(
        &mut self,
        key: Option<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        editor.scroll_to = key;
        let row = key.and_then(|key| editor.draft.row(key));
        match row {
            Some(row) => match &row.inputs.label {
                Some(label) if label.read(cx).value().is_empty() => {
                    label.update(cx, |label, cx| label.focus(window, cx));
                }
                _ => {
                    let code = row.field_type == PersonalFieldType::Totp;
                    row.inputs.value.update(cx, |value, cx| {
                        if code && value.is_masked() {
                            value.set_masked(false, cx);
                        }
                        value.focus(window, cx);
                    });
                }
            },
            None => self.item_name.update(cx, |name, cx| name.focus(window, cx)),
        }
        cx.notify();
    }

    fn editor_values(&self, cx: &App) -> HashMap<usize, RowValue> {
        self.item_editor
            .as_ref()
            .map_or_else(HashMap::new, |editor| {
                editor
                    .draft
                    .rows()
                    .filter_map(|row| read_inputs(&row.inputs, cx).map(|value| (row.key, value)))
                    .collect()
            })
    }

    pub(super) fn item_editor_changed(&self, cx: &App) -> bool {
        let Some(editor) = &self.item_editor else {
            return false;
        };
        let name = self.item_name.read(cx).value();
        if editor.is_new() {
            return !name.trim().is_empty() || editor.draft.has_content(&self.editor_values(cx));
        }
        let base = self.personal_detail.item();
        match (
            base,
            editor
                .draft
                .build(base, &name, |inputs| read_inputs(inputs, cx)),
        ) {
            (Some(base), Ok(item)) => item != *base,
            _ => true,
        }
    }

    pub(super) fn save_item_editor(&mut self, cx: &mut Context<Self>) -> bool {
        self.write_item_editor(false, cx)
    }

    fn write_item_editor(&mut self, salvage: bool, cx: &mut Context<Self>) -> bool {
        let Some(editor) = &self.item_editor else {
            return true;
        };
        if !self.is_unsealed() {
            return false;
        }
        let name = self.item_name.read(cx).value();
        let base = (!editor.is_new())
            .then(|| self.personal_detail.item())
            .flatten();
        if !editor.is_new() && base.is_none() {
            return false;
        }
        let read = |inputs: &Inputs| read_inputs(inputs, cx);
        let built = if salvage {
            editor.draft.salvage(base, &name, read)
        } else {
            editor.draft.build(base, &name, read)
        };
        let item = match built {
            Ok(item) => item,
            Err(problem) => {
                if let Some(editor) = &mut self.item_editor {
                    editor.scroll_to = match problem.target {
                        Target::Row(key) => Some(key),
                        _ => None,
                    };
                    editor.problems = vec![problem];
                }
                cx.notify();
                return false;
            }
        };
        if base == Some(&item) {
            self.close_item_editor(cx);
            return true;
        }
        if base.is_some() {
            match self.save_personal_item(item) {
                Ok(()) => {
                    self.personal_detail.clear_error();
                    self.close_item_editor(cx);
                    self.update_personal_ticker(cx);
                    self.show_toast("Saved", Some(Direction::Undo), false, cx);
                    true
                }
                Err(PersonalWriteError::Changed(contents)) => {
                    self.apply_personal_contents(contents);
                    self.editor_problem(personal_detail::ITEM_CHANGED.to_owned(), cx);
                    if let Some(VaultSelection::Entry(entry)) = self.selected_vault_item.clone() {
                        self.load_personal_item(*entry, cx);
                    }
                    false
                }
                Err(PersonalWriteError::Failed(error)) => {
                    self.editor_problem(format!("Not saved: {error}"), cx);
                    false
                }
            }
        } else {
            match self.runtime.put_personal_secret(&item, None) {
                Ok((version, contents)) => {
                    self.item_editor = None;
                    self.apply_personal_contents(contents);
                    self.personal_panel = PersonalPanel::Overview;
                    let saved = self.unsealed_contents().and_then(|contents| {
                        contents
                            .entries
                            .iter()
                            .find(|entry| personal_item_id(entry) == Some(item.id.as_str()))
                            .cloned()
                    });
                    match saved {
                        Some(entry) => self.open_saved_personal_item(entry, item, version, cx),
                        None => self.show_personal_panel(PersonalPanel::Overview, cx),
                    }
                    cx.notify();
                    true
                }
                Err(error) => {
                    self.editor_problem(format!("Not saved: {error}"), cx);
                    false
                }
            }
        }
    }

    fn editor_problem(&mut self, message: String, cx: &mut Context<Self>) {
        if let Some(editor) = &mut self.item_editor {
            editor.problems = vec![Problem::new(Target::Item, message)];
            editor.scroll_to = None;
        }
        cx.notify();
    }

    pub(super) fn close_item_editor(&mut self, cx: &mut Context<Self>) {
        if self.item_editor.take().is_none() {
            return;
        }
        self.forget_qr_scan();
        if matches!(self.generator_target, Some(GeneratorTarget::Field(_))) {
            self.close_generator(cx);
        }
        self.reset_personal_inputs(cx);
        cx.notify();
    }

    pub(super) fn cancel_item_editor(&mut self, cx: &mut Context<Self>) {
        let back = |view: &mut Self, cx: &mut Context<Self>| {
            if view.personal_panel == PersonalPanel::NewItem
                && view.selected_vault_item == Some(VaultSelection::PersonalSecrets)
            {
                view.show_personal_panel(PersonalPanel::Overview, cx);
            }
        };
        if self.leave_item_editor(back, cx) {
            back(self, cx);
        }
    }

    pub(super) fn leave_item_editor(
        &mut self,
        retry: impl FnOnce(&mut Self, &mut Context<Self>) + 'static,
        cx: &mut Context<Self>,
    ) -> bool {
        if self.item_editor.is_none() {
            return true;
        }
        if !self.item_editor_changed(cx) {
            self.close_item_editor(cx);
            return true;
        }
        self.item_leave.request = Some(Box::new(retry));
        cx.notify();
        false
    }

    pub(super) fn save_item_editor_on_exit(&mut self, cx: &mut Context<Self>) {
        if self.item_editor_changed(cx) {
            self.write_item_editor(true, cx);
        }
        self.item_editor = None;
        self.item_leave.request = None;
    }

    fn guard_item_editor(&mut self, cx: &mut Context<Self>) {
        let runtime = Arc::clone(&self.runtime);
        let task = cx.spawn(async move |view, cx| {
            loop {
                smol::Timer::after(GUARD_EVERY).await;
                let Ok(metadata) = view.update(cx, |view, _| match &view.snapshot {
                    Snapshot::Unsealed { metadata, .. } => Some(metadata.clone()),
                    _ => None,
                }) else {
                    break;
                };
                let Some(metadata) = metadata else {
                    continue;
                };
                let deadlines = {
                    let runtime = Arc::clone(&runtime);
                    let metadata = metadata.clone();
                    smol::unblock(move || runtime.lease_deadlines(&metadata)).await
                };
                let Some(deadlines) = deadlines else {
                    continue;
                };
                let Ok(touch) = view.update(cx, |view, cx| view.check_item_editor(deadlines, cx))
                else {
                    break;
                };
                if touch {
                    let runtime = Arc::clone(&runtime);
                    let _ = smol::unblock(move || runtime.keep_unsealed(&metadata)).await;
                }
            }
        });
        if let Some(editor) = &mut self.item_editor {
            editor.guard = Some(task);
        }
    }

    fn check_item_editor(&mut self, deadlines: (u64, u64), cx: &mut Context<Self>) -> bool {
        let changed = self.item_editor_changed(cx);
        let Some(editor) = &mut self.item_editor else {
            return false;
        };
        match guard(
            unix_now(),
            deadlines,
            editor.active,
            editor.touched.elapsed(),
            changed,
        ) {
            Guard::Wait => false,
            Guard::Touch => {
                editor.active = false;
                editor.touched = Instant::now();
                true
            }
            Guard::Save => {
                self.write_item_editor(true, cx);
                false
            }
        }
    }

    fn mark_editor_active(&mut self) {
        if let Some(editor) = &mut self.item_editor {
            editor.active = true;
        }
    }

    pub(super) fn open_leave_dialog(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.item_leave.request.is_none() || self.item_leave.dialog {
            return;
        }
        self.item_leave.dialog = true;
        let name = self.item_name.read(cx).value().trim().to_owned();
        let name = if name.is_empty() {
            self.personal_detail
                .item()
                .filter(|_| self.editing_item())
                .map_or_else(|| "New item".to_owned(), |item| item.title.clone())
        } else {
            name
        };
        let title: SharedString = format!("Save changes to {name}?").into();
        let view = cx.weak_entity();
        let overlay = Rc::clone(&self.shortcuts.overlay);
        overlay.set(true);
        window.open_dialog(cx, move |dialog, _, _| {
            let closing = view.clone();
            let discarding = view.clone();
            let saving = view.clone();
            let overlay = Rc::clone(&overlay);
            dialog
                .on_close(move |_, _, cx| {
                    overlay.set(false);
                    let _ = closing.update(cx, |view, cx| {
                        view.item_leave = Leave::default();
                        cx.notify();
                    });
                })
                .title(title.clone())
                .width(px(440.))
                .close_button(false)
                .child(div().text_body().child("Your changes are not saved yet."))
                .footer(
                    DialogFooter::new()
                        .child(
                            button("discard-changes")
                                .icon(Glyph::Trash)
                                .label("Discard")
                                .on_click(move |_, window, cx| {
                                    let _ = discarding
                                        .update(cx, |view, cx| view.finish_leave(false, cx));
                                    window.close_dialog(cx);
                                }),
                        )
                        .child(div().flex_1())
                        .child(
                            button("keep-editing")
                                .icon(Glyph::Pencil)
                                .label("Keep editing")
                                .on_click(|_, window, cx| {
                                    window.dispatch_action(Box::new(CancelDialog), cx);
                                }),
                        )
                        .child(
                            button("save-changes")
                                .primary()
                                .icon(IconName::Check)
                                .label("Save")
                                .on_click(move |_, window, cx| {
                                    let _ =
                                        saving.update(cx, |view, cx| view.finish_leave(true, cx));
                                    window.close_dialog(cx);
                                }),
                        ),
                )
        });
    }

    fn finish_leave(&mut self, save: bool, cx: &mut Context<Self>) {
        let request = std::mem::take(&mut self.item_leave).request;
        self.shortcuts.overlay.set(false);
        if save {
            if !self.save_item_editor(cx) {
                return;
            }
        } else {
            self.close_item_editor(cx);
        }
        if let Some(request) = request {
            request(self, cx);
        }
    }

    fn add_field(&mut self, addable: Addable, window: &mut Window, cx: &mut Context<Self>) {
        if self.item_editor.is_some() {
            self.editor_add(addable, window, cx);
        } else {
            self.begin_edit(EditStart::Add(addable), window, cx);
        }
    }

    fn editor_add(&mut self, addable: Addable, window: &mut Window, cx: &mut Context<Self>) {
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        if let Addable::Row { key, .. } = addable {
            if editor.draft.show(key) {
                editor.arrived.insert(key);
                self.focus_editor_row(Some(key), window, cx);
            }
            return;
        }
        let revealed = HashSet::new();
        let key = match addable {
            Addable::Row { .. } => None,
            Addable::Template { id, .. } => editor
                .draft
                .insert_template(&id, |seed| make_inputs(seed, &revealed, window, cx)),
            Addable::Website => editor
                .draft
                .insert_website(|seed| make_inputs(seed, &revealed, window, cx)),
            Addable::Custom(field_type) => Some(
                editor
                    .draft
                    .insert_custom(field_type, |seed| make_inputs(seed, &revealed, window, cx)),
            ),
        };
        let Some(key) = key else {
            return;
        };
        self.watch_new_row(key, cx);
        self.focus_editor_row(Some(key), window, cx);
    }

    fn watch_new_row(&mut self, key: usize, cx: &mut Context<Self>) {
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        editor.arrived.insert(key);
        let inputs = editor.draft.row(key).map(|row| Inputs {
            value: row.inputs.value.clone(),
            label: row.inputs.label.clone(),
        });
        if let Some(inputs) = inputs {
            let subscriptions = watch_row(key, &inputs, cx);
            if let Some(editor) = &mut self.item_editor {
                editor.subscriptions.extend(subscriptions);
            }
        }
    }

    pub(super) fn qr_target(&self) -> Option<QrTarget> {
        if !self.is_unsealed() || self.settings_open {
            return None;
        }
        Some(match &self.item_editor {
            Some(editor) => editor
                .item_id
                .clone()
                .map_or(QrTarget::NewItem, QrTarget::Item),
            None => self
                .personal_detail
                .item()
                .map_or(QrTarget::Vault, |item| QrTarget::Item(item.id.clone())),
        })
    }

    pub(super) fn use_qr_code(
        &mut self,
        link: &str,
        row: Option<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.item_editor.is_none() {
            let kept = self
                .personal_detail
                .item()
                .and_then(one_time_value)
                .is_some_and(|value| totp::same_key(value, link));
            if kept {
                self.show_toast(ONE_TIME_KEPT, None, false, cx);
                return;
            }
            self.begin_edit(EditStart::Top, window, cx);
        }
        let Some(key) = self.show_one_time_row(row, window, cx) else {
            return;
        };
        let values = self.editor_values(cx);
        let replacing = self
            .item_editor
            .as_ref()
            .filter(|editor| !editor.is_new())
            .zip(self.personal_detail.item())
            .is_some_and(|(editor, item)| editor.draft.replaced(item, &values).contains(&key));
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        editor
            .problems
            .retain(|problem| problem.target != Target::Row(key));
        editor.scroll_to = Some(key);
        let Some(value) = editor.draft.row(key).map(|row| row.inputs.value.clone()) else {
            return;
        };
        if totp::same_key(&value.read(cx).value(), link) {
            if !replacing {
                editor.notices.insert(key, ONE_TIME_KEPT);
            }
            cx.notify();
            return;
        }
        value.update(cx, |input, cx| {
            input.replace(link, cx);
            input.set_masked(true, cx);
        });
        self.editor_value_changed(key, cx);
    }

    pub(super) fn fill_from_one_time_link(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(editor) = self
            .item_editor
            .as_mut()
            .filter(|editor| editor.origin_pending)
        else {
            return;
        };
        editor.origin_pending = false;
        let link = editor
            .draft
            .field_rows()
            .find(|row| row.field_type == PersonalFieldType::Totp && !row.removed)
            .map(|row| row.inputs.value.clone());
        let username = editor
            .draft
            .field_rows()
            .find(|row| row.id == USERNAME_ID && !row.removed && !row.hidden)
            .map(|row| (row.key, row.inputs.value.clone()));
        let Some(link) = link
            .map(|input| input.read(cx).value())
            .filter(|link| Totp::parse(link).is_some())
        else {
            return;
        };
        let origin = totp::origin(&link);
        if let Some(issuer) = origin.issuer
            && self.item_name.read(cx).value().trim().is_empty()
        {
            self.item_name
                .update(cx, |name, cx| name.set_value(issuer, window, cx));
        }
        if let (Some(account), Some((username, input))) = (origin.account, username)
            && input.read(cx).value().is_empty()
        {
            input.update(cx, |input, cx| input.replace(&account, cx));
            self.editor_value_changed(username, cx);
        }
    }

    fn show_one_time_row(
        &mut self,
        row: Option<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Option<usize> {
        let editor = self.item_editor.as_mut()?;
        let existing = one_time_row(&editor.draft, row)
            .or_else(|| {
                editor
                    .draft
                    .field_rows()
                    .find(|row| row.field_type == PersonalFieldType::Totp)
            })
            .map(|row| (row.key, row.removed, row.hidden));
        if let Some((key, removed, hidden)) = existing {
            if removed {
                editor.draft.restore(key);
            }
            if hidden {
                editor.draft.show(key);
            }
            if removed || hidden {
                editor.arrived.insert(key);
            }
            return Some(key);
        }
        let revealed = HashSet::new();
        let template = template_fields(editor.draft.kind)
            .into_iter()
            .find(|field| field.field_type == PersonalFieldType::Totp);
        let key = match template {
            Some(field) => editor
                .draft
                .insert_template(&field.id, |seed| make_inputs(seed, &revealed, window, cx))?,
            None => {
                editor
                    .draft
                    .push_custom(ONE_TIME_LABEL, PersonalFieldType::Totp, "", &mut |seed| {
                        make_inputs(seed, &revealed, window, cx)
                    })
            }
        };
        self.watch_new_row(key, cx);
        Some(key)
    }

    pub(super) fn show_qr_problem(
        &mut self,
        message: &'static str,
        row: Option<usize>,
        cx: &mut Context<Self>,
    ) {
        let row = self
            .item_editor
            .as_ref()
            .and_then(|editor| one_time_row(&editor.draft, row))
            .map(|row| row.key);
        match (row, &mut self.item_editor) {
            (Some(key), Some(editor)) => {
                editor
                    .problems
                    .retain(|problem| problem.target != Target::Row(key));
                editor
                    .problems
                    .push(Problem::new(Target::Row(key), message));
                editor.scroll_to = Some(key);
                cx.notify();
            }
            _ => self.show_toast(message, None, true, cx),
        }
    }

    fn editor_remove(&mut self, key: usize, cx: &mut Context<Self>) {
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        let empty = editor
            .draft
            .row(key)
            .is_some_and(|row| row.inputs.value.read(cx).value().is_empty());
        editor.draft.remove(key, empty);
        editor.strengths.remove(&key);
        editor.ratings.remove(&key);
        editor
            .problems
            .retain(|problem| problem.target != Target::Row(key));
        if self.generator_target == Some(GeneratorTarget::Field(key)) {
            self.close_generator(cx);
        }
        self.update_personal_ticker(cx);
        cx.notify();
    }

    fn editor_restore(&mut self, key: usize, cx: &mut Context<Self>) {
        if let Some(editor) = &mut self.item_editor {
            editor.draft.restore(key);
            editor.arrived.insert(key);
        }
        self.update_personal_ticker(cx);
        cx.notify();
    }

    fn editor_move(&mut self, key: usize, target: usize, cx: &mut Context<Self>) {
        let reduce_motion = cx.reduce_motion();
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        let before = editor.draft.section_keys(key);
        if !editor.draft.move_row(key, target) {
            return;
        }
        if !reduce_motion {
            let after = editor.draft.section_keys(key);
            editor.slide(&before, &after);
        }
        cx.notify();
    }

    fn editor_drag_over(
        &mut self,
        dragged: usize,
        target: usize,
        y: Pixels,
        slot: Bounds<Pixels>,
        cx: &mut Context<Self>,
    ) {
        if dragged == target || y < slot.top() || y >= slot.bottom() {
            return;
        }
        let Some(editor) = &self.item_editor else {
            return;
        };
        let order = editor.draft.section_keys(dragged);
        let position = |key| order.iter().position(|candidate| *candidate == key);
        let (Some(from), Some(to)) = (position(dragged), position(target)) else {
            return;
        };
        let middle = slot.center().y;
        if (from < to && y > middle) || (from > to && y < middle) {
            self.editor_move(dragged, target, cx);
        }
    }

    fn start_editor_drag(&mut self, key: usize, cx: &mut Context<Self>) {
        if let Some(editor) = &mut self.item_editor {
            editor.dragging = Some(key);
            cx.notify();
        }
    }

    fn end_editor_drag(&mut self, cx: &mut Context<Self>) {
        if let Some(editor) = &mut self.item_editor {
            editor.dragging = None;
            cx.notify();
        }
    }

    pub(super) fn animate_item_editor(&mut self, window: &mut Window, cx: &App) {
        let title_focused = self.item_name.focus_handle(cx).is_focused(window);
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        editor.title_focused = title_focused;
        editor.focused_value = editor
            .draft
            .rows()
            .find(|row| row.inputs.value.focus_handle(cx).is_focused(window))
            .map(|row| row.key);
        editor.focused_name = editor
            .draft
            .rows()
            .find(|row| {
                row.inputs
                    .label
                    .as_ref()
                    .is_some_and(|label| label.focus_handle(cx).is_focused(window))
            })
            .map(|row| row.key);
        if !cx.has_active_drag() {
            editor.dragging = None;
        }
        let now = Instant::now();
        editor
            .slides
            .retain(|_, slide| now.duration_since(slide.started) < SLIDE_DURATION);
        if !editor.slides.is_empty() {
            window.request_animation_frame();
        }
    }

    fn editor_set_type(
        &mut self,
        key: usize,
        field_type: PersonalFieldType,
        cx: &mut Context<Self>,
    ) {
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        let masked = field_type.concealed();
        let multiline = is_multiline(&field_type);
        let placeholder = placeholder(&field_type);
        let Some(reshaped) = editor
            .draft
            .row(key)
            .map(|row| is_multiline(&row.field_type) != multiline)
        else {
            return;
        };
        if !editor.draft.set_field_type(key, field_type) {
            return;
        }
        if let Some(row) = editor.draft.row_mut(key) {
            if reshaped {
                let value = row.inputs.value.read(cx).value();
                row.inputs.value = make_value(&value, masked, multiline, placeholder, cx);
            } else {
                row.inputs.value.update(cx, |input, cx| {
                    input.set_masked(masked, cx);
                    input.set_placeholder(placeholder, cx);
                });
            }
        }
        if reshaped {
            self.watch_item_editor(cx);
        }
        if self.generator_target == Some(GeneratorTarget::Field(key)) {
            self.close_generator(cx);
        }
        self.update_personal_ticker(cx);
        cx.notify();
    }

    fn editor_switch_kind(
        &mut self,
        kind: PersonalSecretKind,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let values = self.editor_values(cx);
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        if !editor.is_new() || editor.draft.kind == kind {
            return;
        }
        let revealed = HashSet::new();
        editor.draft = editor.draft.switched(kind, &values, |seed| {
            make_inputs(seed, &revealed, window, cx)
        });
        editor.problems.clear();
        editor.notices.clear();
        editor.strengths.clear();
        editor.ratings.clear();
        self.close_generator(cx);
        self.watch_item_editor(cx);
        self.update_personal_ticker(cx);
        cx.notify();
    }

    fn editor_value_changed(&mut self, key: usize, cx: &mut Context<Self>) {
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        editor.problems.retain(|problem| {
            !matches!(problem.target, Target::Item) && problem.target != Target::Row(key)
        });
        editor.notices.remove(&key);
        let one_time = editor
            .draft
            .row(key)
            .filter(|row| row.field_type == PersonalFieldType::Totp)
            .map(|row| row.inputs.value.clone());
        editor.origin_pending |= one_time.is_some() && editor.is_new();
        let path = one_time
            .as_ref()
            .and_then(|input| qr_codes::file_path(&input.read(cx).value()))
            .filter(|path| path.is_file());
        let kind = editor.draft.kind;
        let rated = editor.draft.row(key).is_some_and(|row| {
            !row.custom && personal_actions::can_generate_value(kind, &row.field_type, &row.id)
        });
        if rated {
            let rating = cx.spawn(async move |view, cx| {
                smol::Timer::after(crate::password_generator::RATING_PAUSE).await;
                let _ = view.update(cx, |view, cx| view.rate_editor_value(key, cx));
            });
            editor.ratings.insert(key, rating);
        }
        if let (Some(input), Some(path)) = (one_time, path) {
            input.update(cx, |input, cx| input.replace("", cx));
            self.read_qr_file(path, Some(key), cx);
        }
        self.update_personal_ticker(cx);
        cx.notify();
    }

    fn rate_editor_value(&mut self, key: usize, cx: &mut Context<Self>) {
        let Some(editor) = &mut self.item_editor else {
            return;
        };
        let Some(value) = editor
            .draft
            .row(key)
            .map(|row| row.inputs.value.read(cx).value())
        else {
            return;
        };
        if value.is_empty() {
            editor.strengths.remove(&key);
        } else {
            editor.strengths.insert(key, Strength::of(&value));
        }
        cx.notify();
    }

    fn toggle_editor_reveal(&mut self, key: usize, cx: &mut Context<Self>) {
        if let Some(row) = self
            .item_editor
            .as_ref()
            .and_then(|editor| editor.draft.row(key))
        {
            row.inputs.value.update(cx, |input, cx| {
                let masked = input.is_masked();
                input.set_masked(!masked, cx);
            });
        }
    }

    pub(super) fn use_generated_editor_value(
        &mut self,
        key: usize,
        password: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some(input) = self
            .item_editor
            .as_ref()
            .and_then(|editor| editor.draft.row(key))
            .map(|row| row.inputs.value.clone())
        else {
            return;
        };
        input.update(cx, |input, cx| {
            input.set_value(password, window, cx);
            input.focus(window, cx);
        });
        self.editor_value_changed(key, cx);
    }

    pub(super) fn editor_has_code(&self, cx: &App) -> bool {
        self.item_editor.as_ref().is_some_and(|editor| {
            editor.draft.rows().any(|row| {
                !row.removed
                    && row.field_type == PersonalFieldType::Totp
                    && Totp::parse(&row.inputs.value.read(cx).value()).is_some()
            })
        })
    }

    pub(super) fn render_editor_title(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let problem = self
            .item_editor
            .as_ref()
            .and_then(|editor| editor.problem(Target::Name))
            .map(ToOwned::to_owned);
        let focused = self
            .item_editor
            .as_ref()
            .is_some_and(|editor| editor.title_focused);
        v_flex()
            .flex_1()
            .min_w_0()
            .child(
                div()
                    .id("editor-title")
                    .group("editor-title")
                    .relative()
                    .ml(-TITLE_INSET)
                    .my(-TITLE_SPREAD)
                    .child(value_fill(
                        "editor-title",
                        "editor-title".into(),
                        focused,
                        false,
                        px(0.),
                        cx,
                    ))
                    .child(Styled::h(
                        Input::new(&self.item_name)
                            .appearance(false)
                            .text_title()
                            .font_semibold()
                            .line_height(gpui::phi())
                            .px(TITLE_INSET)
                            .py_0(),
                        TITLE_LINE + TITLE_SPREAD * 2.,
                    )),
            )
            .when_some(problem, |column, problem| {
                column.child(div().text_caption().text_color(theme.danger).child(problem))
            })
    }

    pub(super) fn render_editor_buttons(cx: &mut Context<Self>) -> Div {
        h_flex()
            .flex_none()
            .ml_auto()
            .gap_2()
            .child(
                button("cancel-item-edit")
                    .icon(IconName::Close)
                    .label("Cancel")
                    .on_click(cx.listener(|view, _, _, cx| view.cancel_item_editor(cx))),
            )
            .child(
                button("save-item-edit")
                    .primary()
                    .icon(IconName::Check)
                    .label("Save")
                    .on_click(cx.listener(|view, _, _, cx| {
                        view.save_item_editor(cx);
                    })),
            )
    }

    pub(super) fn render_new_item(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let Some(editor) = &self.item_editor else {
            return div();
        };
        let kind = editor.draft.kind;
        v_flex()
            .w_full()
            .max_w(personal_detail::CONTENT_WIDTH)
            .mx_auto()
            .gap_6()
            .p_6()
            .child(
                h_flex()
                    .flex_wrap()
                    .items_center()
                    .gap_x_5()
                    .gap_y_3()
                    .child(personal_icon_tile(kind, 56. / 16., &theme))
                    .child(
                        v_flex()
                            .flex_grow(1.)
                            .flex_basis(TITLE_BASIS)
                            .min_w_0()
                            .gap_1()
                            .child(
                                h_flex()
                                    .min_w_0()
                                    .items_center()
                                    .gap_2()
                                    .child(self.render_editor_title(cx)),
                            )
                            .child(Self::render_kind_picker(kind, cx)),
                    )
                    .child(Self::render_editor_buttons(cx)),
            )
            .child(self.render_item_editor(cx))
    }

    fn render_kind_picker(kind: PersonalSecretKind, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let view = cx.entity().downgrade();
        h_flex().child(
            button("editor-kind-picker")
                .ghost()
                .small()
                .ml(-KIND_INSET)
                .my(px(-2.))
                .px(KIND_INSET)
                .text_body()
                .text_color(theme.muted_foreground)
                .label(kind.label())
                .dropdown_caret(true)
                .dropdown_menu(move |mut menu, _, _| {
                    menu = menu.check_side(Side::Right);
                    for option in PersonalSecretKind::ALL {
                        let view = view.clone();
                        menu = menu.item(
                            PopupMenuItem::new(option.label())
                                .icon(personal_kind_icon(option))
                                .checked(option == kind)
                                .on_click(move |_, window, cx| {
                                    let _ = view.update(cx, |view, cx| {
                                        view.editor_switch_kind(option, window, cx);
                                    });
                                }),
                        );
                    }
                    menu
                }),
        )
    }

    pub(super) fn render_item_editor(&self, cx: &mut Context<Self>) -> Div {
        let theme = cx.theme().clone();
        let Some(editor) = &self.item_editor else {
            return div();
        };
        let (changed, replaced) = self
            .personal_detail
            .item()
            .filter(|_| !editor.is_new())
            .map(|item| {
                let values = self.editor_values(cx);
                (
                    editor.draft.changed(item, &values),
                    editor.draft.replaced(item, &values),
                )
            })
            .unwrap_or_default();
        let mut groups = v_flex().w_full().gap_4();
        let visible = |section: &&Section<Inputs>| section.rows.iter().any(|row| !row.hidden);
        let grouped = editor.draft.sections.iter().filter(visible).count() > 1;
        for section in editor.draft.sections.iter().filter(visible) {
            let heading = (grouped
                && !section
                    .label
                    .eq_ignore_ascii_case(editor.draft.kind.label()))
            .then(|| section.label.clone().into());
            let rows: Vec<_> = section
                .rows
                .iter()
                .filter(|row| !row.hidden)
                .map(|row| {
                    let marks = Marks {
                        changed: changed.contains(&row.key),
                        replaced: replaced.contains(&row.key),
                    };
                    self.render_editor_row(editor, row, true, marks, cx)
                })
                .collect();
            groups = groups.child(field_group(heading, rows, cx));
        }
        if let Some(notes) = editor.draft.notes.as_ref().filter(|notes| !notes.hidden) {
            groups = groups.child(field_group(
                None,
                [self.render_editor_row(
                    editor,
                    notes,
                    false,
                    Marks {
                        changed: changed.contains(&notes.key),
                        replaced: false,
                    },
                    cx,
                )],
                cx,
            ));
        }
        v_flex()
            .w_full()
            .gap_4()
            .capture_key_down(cx.listener(|view, _, _, _| view.mark_editor_active()))
            .capture_any_mouse_down(cx.listener(|view, _, _, _| view.mark_editor_active()))
            .child(groups)
            .child(h_flex().child(Self::render_editor_add_field(editor.draft.addable(), cx)))
            .when_some(editor.problem(Target::Item), |panel, message| {
                panel.child(error_banner(message.to_owned(), theme.danger))
            })
    }

    pub(super) fn render_editor_add_field(
        addable: Vec<Addable>,
        cx: &mut Context<Self>,
    ) -> impl IntoElement {
        let view = cx.entity().downgrade();
        button("editor-add-field")
            .ghost()
            .icon(IconName::Plus)
            .label("Add field")
            .dropdown_menu(move |mut menu, window, cx| {
                for field in &addable {
                    let view = view.clone();
                    let picked = field.clone();
                    menu = menu.item(
                        PopupMenuItem::new(field.label().to_owned())
                            .icon(field.icon())
                            .on_click(move |_, window, cx| {
                                let _ = view.update(cx, |view, cx| {
                                    view.add_field(picked.clone(), window, cx);
                                });
                            }),
                    );
                }
                let view = view.clone();
                with_custom_fields(menu, window, cx, move |field_type, window, cx| {
                    let _ = view.update(cx, |view, cx| {
                        view.add_field(Addable::Custom(field_type), window, cx);
                    });
                })
            })
    }

    fn editor_row_label(row: &Row<Inputs>, cx: &App) -> String {
        row.inputs
            .label
            .as_ref()
            .map(|label| label.read(cx).value().trim().to_owned())
            .filter(|label| !label.is_empty())
            .unwrap_or_else(|| {
                if row.custom && row.label.trim().is_empty() {
                    CUSTOM_LABEL.to_owned()
                } else {
                    row.label.clone()
                }
            })
    }

    #[allow(clippy::too_many_lines)]
    fn render_editor_row(
        &self,
        editor: &Editor,
        row: &Row<Inputs>,
        draggable: bool,
        marks: Marks,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let changed = marks.changed;
        let theme = cx.theme().clone();
        let key = row.key;
        let icon = personal_field_icon(&row.id, &row.field_type)
            .size(rems(1.))
            .text_color(theme.muted_foreground);
        let label_text = Self::editor_row_label(row, cx);
        let scroll_to = (editor.scroll_to == Some(key)).then(|| self.scroll_to_editor_row(cx));
        if row.removed {
            let content = crate::motion::enter(
                ("editor-removed-enter", key),
                field_row(("editor-removed", key), true, cx)
                    .children(scroll_to)
                    .child(
                        field_label(
                            icon,
                            div().min_w_0().truncate().line_through().child(label_text),
                            theme.muted_foreground,
                        )
                        .flex_1()
                        .opacity(0.55),
                    )
                    .child(
                        field_actions().child(
                            button(("restore-field", key))
                                .ghost()
                                .icon(IconName::Undo2)
                                .label("Restore")
                                .on_click(cx.listener(move |view, _, _, cx| {
                                    view.editor_restore(key, cx);
                                })),
                        ),
                    ),
            );
            return Self::editor_slot(editor, key, draggable, content, cx);
        }
        let value = row.inputs.value.read(cx).value();
        let empty = value.is_empty();
        let masked = row.inputs.value.read(cx).is_masked();
        let secret = row.concealed || row.field_type.concealed();
        let code = (row.field_type == PersonalFieldType::Totp)
            .then(|| Totp::parse(&value))
            .flatten()
            .map(|totp| Self::render_personal_code(key, &totp, cx));
        let code_only = code.is_some() && masked;
        let (boxed_code, code) = if code_only {
            (code, None)
        } else {
            (None, code)
        };
        let strength = editor
            .strengths
            .get(&key)
            .map(|strength| Self::render_personal_strength(*strength, cx));
        let can_generate = (!row.custom || editor.draft.kind == PersonalSecretKind::Generic)
            && personal_actions::can_generate_value(editor.draft.kind, &row.field_type, &row.id);
        let removable = draggable || !empty;
        let focused = editor.focused_value == Some(key) || editor.focused_name == Some(key);
        let row_group: SharedString = format!("editor-row-{key}").into();
        let label: gpui::AnyElement = match &row.inputs.label {
            Some(label) => {
                let group: SharedString = format!("editor-name-{key}").into();
                div()
                    .id(("editor-name", key))
                    .group(group.clone())
                    .relative()
                    .size_full()
                    .flex()
                    .items_center()
                    .child(value_fill(
                        &format!("editor-name-{key}"),
                        group,
                        editor.focused_name == Some(key),
                        false,
                        LABEL_BLEED,
                        cx,
                    ))
                    .child(
                        Input::new(label)
                            .appearance(false)
                            .flex_1()
                            .text_body()
                            .text_color(theme.foreground)
                            .px_0()
                            .py_0(),
                    )
                    .child(div().relative().flex_none().pr_1().child({
                        let view = cx.entity().downgrade();
                        field_kind_picker(
                            ("editor-type", key),
                            &row.field_type,
                            move |field_type, cx| {
                                let _ = view.update(cx, |view, cx| {
                                    view.editor_set_type(key, field_type, cx);
                                });
                            },
                        )
                    }))
                    .into_any_element()
            }
            None => div()
                .id(("editor-label-text", key))
                .size_full()
                .flex()
                .items_center()
                .cursor_text()
                .on_mouse_down(
                    gpui::MouseButton::Left,
                    cx.listener(move |view, _, window, cx| {
                        view.focus_editor_row(Some(key), window, cx);
                    }),
                )
                .child(div().min_w_0().truncate().child(label_text.clone()))
                .into_any_element(),
        };
        let size = editor.slots.borrow().get(&key).map(|slot| slot.size);
        let dragged = DraggedRow {
            key,
            label: label_text.into(),
            size,
        };
        let view = cx.entity().downgrade();
        let grip_group: SharedString = format!("editor-grip-{key}").into();
        let grip_hover = theme.foreground;
        let handle: gpui::AnyElement = if draggable {
            div()
                .id(("editor-grip", key))
                .group(grip_group.clone())
                .absolute()
                .top(px(-8.))
                .left(px(-8.))
                .size_8()
                .flex()
                .items_center()
                .justify_center()
                .cursor_grab()
                .child(hidden_on_hover(
                    ("editor-icon", key),
                    row_group.clone(),
                    div().child(icon),
                ))
                .child(
                    shown_on_hover(
                        ("editor-grip-icon", key),
                        row_group.clone(),
                        false,
                        div()
                            .absolute()
                            .inset_0()
                            .flex()
                            .items_center()
                            .justify_center(),
                    )
                    .child(
                        div()
                            .id(("editor-grip-color", key))
                            .transitions(|transitions| {
                                transitions.text_color(crate::motion::hover())
                            })
                            .text_color(theme.muted_foreground)
                            .group_hover(grip_group, |style| style.text_color(grip_hover))
                            .child(Icon::from(Glyph::Grip).small()),
                    ),
                )
                .on_drag(dragged, move |drag, _, _, cx| {
                    let _ = view.update(cx, |view, cx| view.start_editor_drag(drag.key, cx));
                    cx.new(|_| drag.clone())
                })
                .into_any_element()
        } else {
            icon.into_any_element()
        };
        let message = editor
            .problem(Target::Row(key))
            .map(|problem| (problem.to_owned(), theme.danger))
            .or_else(|| {
                let notice = editor.notices.get(&key)?;
                Some(((*notice).to_owned(), theme.muted_foreground))
            })
            .or_else(|| {
                marks
                    .replaced
                    .then(|| (ONE_TIME_REPLACED.to_owned(), theme.warning))
            });
        let mut generator = if can_generate {
            self.render_generator(GeneratorTarget::Field(key), true, ButtonVariants::ghost, cx)
        } else {
            Vec::new()
        };
        let anchor = generator.split_off(generator.len().min(1));
        let actions = field_actions()
            .child(action_slot().when(secret, |slot| {
                slot.child(
                    button(("editor-reveal", key))
                        .ghost()
                        .icon(if masked {
                            IconName::Eye
                        } else {
                            IconName::EyeOff
                        })
                        .tooltip(if masked { "Reveal" } else { "Hide" })
                        .on_click(cx.listener(move |view, _, _, cx| {
                            view.toggle_editor_reveal(key, cx);
                        })),
                )
            }))
            .child(
                action_slot()
                    .children(generator)
                    .when(row.field_type == PersonalFieldType::Totp, |slot| {
                        slot.child(self.qr_button(key, cx))
                    }),
            )
            .child(
                shown_on_hover(
                    ("editor-tools", key),
                    row_group.clone(),
                    focused,
                    action_slot(),
                )
                .when(removable, |slot| {
                    slot.child(
                        button(("editor-remove", key))
                            .ghost()
                            .icon(Glyph::Trash)
                            .tooltip("Remove field")
                            .on_click(cx.listener(move |view, _, _, cx| {
                                view.editor_remove(key, cx);
                            })),
                    )
                }),
            );
        let label_color = if changed {
            theme.warning
        } else {
            theme.muted_foreground
        };
        let value_group: SharedString = format!("editor-value-{key}").into();
        let value_box = div()
            .id(("editor-value", key))
            .group(value_group.clone())
            .relative()
            .w_full()
            .child(value_fill(
                &format!("editor-value-{key}"),
                value_group,
                editor.focused_value == Some(key),
                changed,
                px(0.),
                cx,
            ))
            .map(|value_box| {
                if code_only {
                    value_box
                        .cursor_text()
                        .on_mouse_down(
                            gpui::MouseButton::Left,
                            cx.listener(move |view, _, window, cx| {
                                view.focus_editor_row(Some(key), window, cx);
                            }),
                        )
                        .children(boxed_code)
                } else {
                    value_box.child(row.inputs.value.clone())
                }
            });
        let line = field_row(("editor-row", key), true, cx)
            .group(row_group)
            .children(scroll_to)
            .children(anchor)
            .child(
                field_label(handle, label, label_color)
                    .id(("editor-label", key))
                    .transitions(|transitions| transitions.text_color(crate::motion::change()))
                    .text_color(label_color),
            )
            .child(
                field_body()
                    .child(
                        field_value()
                            .child(value_box)
                            .children(code)
                            .children(strength)
                            .when_some(message, |column, (message, color)| {
                                column.child(
                                    div().px_3().text_caption().text_color(color).child(message),
                                )
                            }),
                    )
                    .child(crate::motion::fade(("editor-actions", key), actions)),
            );
        let content = if editor.arrived.contains(&key) {
            crate::motion::enter(("editor-row-enter", key), line).into_any_element()
        } else {
            line.into_any_element()
        };
        Self::editor_slot(editor, key, draggable, content, cx)
    }

    fn editor_slot(
        editor: &Editor,
        key: usize,
        draggable: bool,
        content: impl IntoElement,
        cx: &mut Context<Self>,
    ) -> gpui::AnyElement {
        let slots = Rc::clone(&editor.slots);
        let dragged = editor.dragging == Some(key);
        let theme = cx.theme().clone();
        div()
            .id(("editor-slot", key))
            .relative()
            .w_full()
            .child(
                div().absolute().inset_0().child(
                    canvas(
                        move |bounds, _, _| {
                            slots.borrow_mut().insert(key, bounds);
                        },
                        |_, (), _, _| {},
                    )
                    .size_full(),
                ),
            )
            .when(draggable, |slot| {
                slot.on_drag_move(cx.listener(
                    move |view, event: &DragMoveEvent<DraggedRow>, _, cx| {
                        let dragged = event.drag(cx).key;
                        view.editor_drag_over(
                            dragged,
                            key,
                            event.event.position.y,
                            event.bounds,
                            cx,
                        );
                    },
                ))
                .on_drop(cx.listener(|view, _: &DraggedRow, _, cx| view.end_editor_drag(cx)))
            })
            .child(
                div()
                    .relative()
                    .top(px(editor.offset(key, Instant::now())))
                    .when(dragged, |slot| {
                        slot.child(
                            div()
                                .absolute()
                                .inset_0()
                                .my_0p5()
                                .rounded(theme.radius)
                                .bg(theme.secondary.opacity(0.6)),
                        )
                    })
                    .child(
                        div()
                            .when(dragged, |content| content.opacity(0.))
                            .child(content),
                    ),
            )
            .into_any_element()
    }

    fn scroll_to_editor_row(&self, cx: &mut Context<Self>) -> Div {
        let scroll = self.personal_detail.scroll_handle();
        let view = cx.entity().downgrade();
        div().absolute().inset_0().child(
            canvas(
                |_, _, _| {},
                move |bounds, (), window, cx| {
                    let offset = scroll.offset();
                    let target = personal_detail::offset_showing(
                        offset.y,
                        scroll.max_offset().y,
                        scroll.bounds(),
                        bounds.dilate(px(16.)),
                    );
                    if target != offset.y {
                        scroll.set_offset(gpui::point(offset.x, target));
                        window.refresh();
                    }
                    let _ = view.update(cx, |view, _| {
                        if let Some(editor) = &mut view.item_editor {
                            editor.scroll_to = None;
                        }
                    });
                },
            )
            .size_full(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Fake = (String, Option<String>);

    fn fake(seed: Seed<'_>) -> Fake {
        (
            seed.value.to_owned(),
            seed.custom.then(|| seed.label.to_owned()),
        )
    }

    const UNREADABLE: &str = "\u{0}";

    fn read(inputs: &Fake) -> Option<RowValue> {
        (inputs.0 != UNREADABLE).then(|| RowValue {
            value: Zeroizing::new(inputs.0.clone()),
            label: inputs.1.clone().map(Zeroizing::new),
        })
    }

    fn values(draft: &Draft<Fake>) -> HashMap<usize, RowValue> {
        draft
            .rows()
            .filter_map(|row| read(&row.inputs).map(|value| (row.key, value)))
            .collect()
    }

    fn set(draft: &mut Draft<Fake>, id: &str, value: &str) -> usize {
        let row = draft
            .sections
            .iter_mut()
            .flat_map(|section| &mut section.rows)
            .chain(&mut draft.notes)
            .find(|row| row.id == id)
            .unwrap();
        value.clone_into(&mut row.inputs.0);
        row.key
    }

    fn ids(item: &PersonalSecret) -> Vec<&str> {
        item.sections
            .iter()
            .flat_map(|section| &section.fields)
            .map(|field| field.id.as_str())
            .collect()
    }

    fn login() -> PersonalSecret {
        let mut item = PersonalSecret::template(PersonalSecretKind::Login, "GitHub".into());
        for (field, value) in
            item.sections[0]
                .fields
                .iter_mut()
                .zip(["alice", "hunter2", "https://github.com"])
        {
            field.value = value.into();
        }
        item.notes = Some("note".into());
        item
    }

    #[test]
    fn one_time_password_keys_are_cleaned_and_checked_when_saved() {
        let item = login();
        let mut draft = Draft::from_item(&item, fake);
        set(&mut draft, "totp", " jbsw y3dp ehpk 3pxp== ");
        let saved = draft.build(Some(&item), "GitHub", read).unwrap();
        assert_eq!(one_time_value(&saved), Some("JBSWY3DPEHPK3PXP"));
        let key = set(&mut draft, "totp", "JBSWY3DP!");
        assert_eq!(
            draft.build(Some(&item), "GitHub", read).err(),
            Some(Problem::new(
                Target::Row(key),
                "This is not a valid setup key."
            ))
        );
        assert_eq!(
            one_time_value(&draft.salvage(Some(&item), "GitHub", read).unwrap()),
            Some("JBSWY3DP!")
        );
    }

    #[test]
    fn only_a_different_one_time_password_replaces_the_saved_one() {
        let mut item = login();
        let mut draft = Draft::from_item(&item, fake);
        set(&mut draft, "totp", "JBSWY3DPEHPK3PXP");
        assert!(draft.replaced(&item, &values(&draft)).is_empty());
        item.sections[0].fields[3].value = "JBSWY3DPEHPK3PXP".into();
        let mut draft = Draft::from_item(&item, fake);
        set(&mut draft, "totp", "jbsw y3dp ehpk 3pxp");
        assert!(draft.replaced(&item, &values(&draft)).is_empty());
        set(
            &mut draft,
            "totp",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP",
        );
        assert!(draft.replaced(&item, &values(&draft)).is_empty());
        let key = set(&mut draft, "totp", "GEZDGNBVGY3TQOJQ");
        assert_eq!(draft.replaced(&item, &values(&draft)), HashSet::from([key]));
        set(&mut draft, "totp", "");
        assert!(draft.replaced(&item, &values(&draft)).is_empty());
        set(&mut draft, "totp", "GEZDGNBVGY3TQOJQ");
        draft.remove(key, false);
        assert!(draft.replaced(&item, &values(&draft)).is_empty());
        item.sections[0].fields[3].value = "steam://JBSWY3DPEHPK3PXP".into();
        let mut draft = Draft::from_item(&item, fake);
        assert!(draft.replaced(&item, &values(&draft)).is_empty());
        let key = set(&mut draft, "totp", "GEZDGNBVGY3TQOJQ");
        assert_eq!(draft.replaced(&item, &values(&draft)), HashSet::from([key]));
    }

    #[test]
    fn stored_one_time_password_keys_are_kept_until_they_are_edited() {
        let mut item = login();
        item.sections[0].fields[3].value = "not a key".into();
        let draft = Draft::from_item(&item, fake);
        assert_eq!(
            one_time_value(&draft.build(Some(&item), "GitHub", read).unwrap()),
            Some("not a key")
        );
    }

    #[test]
    fn unchanged_items_build_back_to_themselves() {
        let mut item = login();
        item.favorite = true;
        item.tags.push("work".into());
        item.sections.push(PersonalSection {
            id: "imported".into(),
            label: "Imported".into(),
            fields: Vec::new(),
        });
        item.sections.push(PersonalSection {
            id: CUSTOM_SECTION.into(),
            label: CUSTOM_SECTION_LABEL.into(),
            fields: vec![
                PersonalField::new("custom-0", "PIN", PersonalFieldType::Concealed, "1234"),
                PersonalField::new(
                    "custom-1",
                    "Home",
                    PersonalFieldType::Address,
                    serde_json::json!({"city": "Kyiv", "zip": 1000}),
                ),
                PersonalField::new(
                    "custom-2",
                    "Empty",
                    PersonalFieldType::Email,
                    serde_json::Value::Null,
                ),
            ],
        });
        let draft = Draft::from_item(&item, fake);
        assert_eq!(draft.build(Some(&item), "GitHub", read).unwrap(), item);
        assert_eq!(draft.build(Some(&item), " GitHub ", read).unwrap(), item);
    }

    #[test]
    fn qr_codes_go_to_the_one_time_password_row_they_were_scanned_for() {
        let mut draft = Draft::from_item(&login(), fake);
        let key = |draft: &Draft<Fake>, id: &str| {
            draft.field_rows().find(|row| row.id == id).unwrap().key
        };
        let template = key(&draft, "totp");
        let password = key(&draft, "password");
        let custom = draft.push_custom(ONE_TIME_LABEL, PersonalFieldType::Totp, "", &mut fake);
        draft.show(template);
        let picked = |draft: &Draft<Fake>, row| one_time_row(draft, row).map(|row| row.key);
        assert_eq!(picked(&draft, Some(custom)), Some(custom));
        assert_eq!(picked(&draft, Some(password)), Some(template));
        assert_eq!(picked(&draft, None), Some(template));
        draft.remove(template, true);
        assert_eq!(picked(&draft, Some(template)), Some(custom));
    }

    #[test]
    fn new_items_need_a_name_and_one_value() {
        let mut draft = Draft::new_item(PersonalSecretKind::Login, fake);
        assert_eq!(
            draft.build(None, " ", read).unwrap_err(),
            Problem::new(Target::Name, NAME_MISSING)
        );
        assert_eq!(
            draft.build(None, "GitHub", read).unwrap_err(),
            Problem::new(Target::Item, NOTHING_ENTERED)
        );
        assert!(!draft.has_content(&values(&draft)));
        set(&mut draft, "username", "alice");
        assert!(draft.has_content(&values(&draft)));
        let item = draft.build(None, "GitHub", read).unwrap();
        assert_eq!(item.title, "GitHub");
        assert_eq!(ids(&item), ["username", "password", "url-0", "totp"]);
        assert_eq!(item.username(), Some("alice"));
        assert_eq!(item.notes, None);
    }

    #[test]
    fn removed_fields_are_left_out_until_restored() {
        let item = login();
        let mut draft = Draft::from_item(&item, fake);
        let password = draft.key_at(1).unwrap();
        draft.remove(password, false);
        assert!(draft.row(password).unwrap().removed);
        let removed = draft.build(Some(&item), "GitHub", read).unwrap();
        assert_eq!(ids(&removed), ["username", "url-0", "totp"]);
        assert!(
            !draft
                .addable()
                .iter()
                .any(|field| field.label() == "Password")
        );
        draft.restore(password);
        assert_eq!(draft.build(Some(&item), "GitHub", read).unwrap(), item);
        let notes = draft.notes.as_ref().unwrap().key;
        draft.remove(notes, false);
        assert_eq!(
            draft.build(Some(&item), "GitHub", read).unwrap().notes,
            None
        );
    }

    #[test]
    fn only_rows_that_differ_from_the_saved_item_count_as_changed() {
        let item = login();
        let mut draft = Draft::from_item(&item, fake);
        assert!(draft.changed(&item, &values(&draft)).is_empty());
        let username = set(&mut draft, "username", "bob");
        let notes = set(&mut draft, "notes", "new note");
        assert_eq!(
            draft.changed(&item, &values(&draft)),
            HashSet::from([username, notes])
        );
        set(&mut draft, "username", "alice");
        set(&mut draft, "notes", "note");
        let password = draft.key_at(1).unwrap();
        draft.remove(password, false);
        assert!(draft.changed(&item, &values(&draft)).is_empty());
        let custom = draft.insert_custom(PersonalFieldType::Concealed, fake);
        assert_eq!(
            draft.changed(&item, &values(&draft)),
            HashSet::from([custom])
        );
    }

    #[test]
    fn custom_rows_change_with_their_name_or_type() {
        let mut item = login();
        item.sections.push(PersonalSection {
            id: CUSTOM_SECTION.into(),
            label: CUSTOM_SECTION_LABEL.into(),
            fields: vec![PersonalField::new(
                "custom-0",
                "PIN",
                PersonalFieldType::Concealed,
                "1234",
            )],
        });
        let mut draft = Draft::from_item(&item, fake);
        let pin = draft.key_at(4).unwrap();
        draft.row_mut(pin).unwrap().inputs.1 = Some(" PIN ".into());
        assert!(draft.changed(&item, &values(&draft)).is_empty());
        draft.row_mut(pin).unwrap().inputs.1 = Some("Door code".into());
        assert_eq!(draft.changed(&item, &values(&draft)), HashSet::from([pin]));
        draft.row_mut(pin).unwrap().inputs.1 = Some("PIN".into());
        draft.set_field_type(pin, PersonalFieldType::Text);
        assert_eq!(draft.changed(&item, &values(&draft)), HashSet::from([pin]));
    }

    #[test]
    fn empty_fields_wait_behind_add_field_until_shown() {
        let item = login();
        let mut draft = Draft::from_item(&item, fake);
        let totp = draft.key_at(3).unwrap();
        let notes = draft.notes.as_ref().unwrap().key;
        let hidden_totp = Addable::Row {
            key: totp,
            id: "totp".into(),
            label: "One-time password".into(),
            field_type: PersonalFieldType::Totp,
        };
        assert!(draft.row(totp).unwrap().hidden);
        assert!(!draft.row(notes).unwrap().hidden);
        assert_eq!(draft.addable(), [hidden_totp.clone(), Addable::Website]);
        assert!(draft.show(totp));
        assert!(!draft.show(totp));
        assert_eq!(draft.addable(), [Addable::Website]);
        draft.remove(totp, true);
        assert_eq!(draft.addable(), [hidden_totp, Addable::Website]);
        assert_eq!(draft.build(Some(&item), "GitHub", read).unwrap(), item);
        let website = draft.insert_website(fake).unwrap();
        draft.remove(website, true);
        assert!(draft.row(website).is_none());
        set(&mut draft, "notes", "");
        draft.remove(notes, true);
        assert_eq!(
            draft.addable().last(),
            Some(&Addable::Row {
                key: notes,
                id: NOTES_ID.into(),
                label: NOTES_LABEL.into(),
                field_type: PersonalFieldType::Multiline,
            })
        );
    }

    #[test]
    fn template_fields_are_added_in_template_order() {
        let mut item = PersonalSecret::new(PersonalSecretKind::Card, "Card".into());
        item.sections.push(PersonalSection {
            id: "card".into(),
            label: "Card".into(),
            fields: vec![PersonalField::new(
                "code",
                "Security code",
                PersonalFieldType::Concealed,
                "1",
            )],
        });
        item.sections.push(PersonalSection {
            id: CUSTOM_SECTION.into(),
            label: CUSTOM_SECTION_LABEL.into(),
            fields: vec![PersonalField::new(
                "custom-0",
                "Extra",
                PersonalFieldType::Text,
                "x",
            )],
        });
        let mut draft = Draft::from_item(&item, fake);
        draft.insert_template("number", fake).unwrap();
        draft.insert_template("pin", fake).unwrap();
        draft.insert_template("bank", fake).unwrap();
        let sections: Vec<_> = draft
            .sections
            .iter()
            .map(|section| {
                (
                    section.id.as_str(),
                    section
                        .rows
                        .iter()
                        .map(|row| row.id.as_str())
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        assert_eq!(
            sections,
            [
                ("card", vec!["number", "code"]),
                ("contactInfo", vec!["bank"]),
                ("details", vec!["pin"]),
                (CUSTOM_SECTION, vec!["custom-0"]),
            ]
        );
        assert_eq!(draft.insert_template("unknown", fake), None);
    }

    #[test]
    fn websites_and_custom_fields_get_fresh_ids() {
        let item = login();
        let mut draft = Draft::from_item(&item, fake);
        let website = draft.insert_website(fake).unwrap();
        assert_eq!(draft.key_at(3), Some(website));
        assert_eq!(draft.row(website).unwrap().id, "url-1");
        let first = draft.insert_custom(PersonalFieldType::Concealed, fake);
        let second = draft.insert_custom(PersonalFieldType::Concealed, fake);
        draft
            .sections
            .iter_mut()
            .flat_map(|section| &mut section.rows)
            .find(|row| row.key == second)
            .unwrap()
            .inputs
            .1 = Some(" Recovery code ".into());
        let mut built = draft.build(Some(&item), "GitHub", read).unwrap();
        let custom = built.sections.pop().unwrap();
        assert_eq!(custom.id, CUSTOM_SECTION);
        let labels: Vec<_> = custom
            .fields
            .iter()
            .map(|field| (field.id.as_str(), field.label.as_str(), field.concealed))
            .collect();
        assert_eq!(
            labels,
            [
                ("custom-0", CUSTOM_LABEL, true),
                ("custom-1", "Recovery code", true)
            ]
        );
        assert_ne!(first, second);
        let card = PersonalSecret::new(PersonalSecretKind::Card, "Card".into());
        assert!(
            !Draft::from_item(&card, fake)
                .addable()
                .contains(&Addable::Website)
        );
    }

    #[test]
    fn moved_rows_slide_from_where_they_were() {
        let heights = HashMap::from([(1, 40.), (2, 80.), (3, 40.)]);
        assert_eq!(
            shifts(&[1, 2, 3], &[2, 1, 3], &heights),
            [(2, 40.), (1, -80.)]
        );
        assert_eq!(
            shifts(&[1, 2, 3], &[2, 3, 1], &heights),
            [(2, 40.), (3, 40.), (1, -120.)]
        );
        assert_eq!(shifts(&[1, 2, 4], &[2, 1, 4], &heights), Vec::new());
    }

    #[test]
    fn rows_move_only_within_their_section() {
        let mut item = login();
        item.sections.push(PersonalSection {
            id: CUSTOM_SECTION.into(),
            label: CUSTOM_SECTION_LABEL.into(),
            fields: vec![PersonalField::new(
                "custom-0",
                "PIN",
                PersonalFieldType::Text,
                "1",
            )],
        });
        let mut draft = Draft::from_item(&item, fake);
        let username = draft.key_at(0).unwrap();
        let website = draft.key_at(2).unwrap();
        let custom = draft.key_at(4).unwrap();
        assert!(draft.move_row(username, website));
        assert!(!draft.move_row(username, custom));
        assert!(!draft.move_row(username, username));
        let moved = draft.build(Some(&item), "GitHub", read).unwrap();
        assert_eq!(
            ids(&moved),
            ["password", "url-0", "username", "totp", "custom-0"]
        );
        assert!(draft.move_row(username, draft.key_at(0).unwrap()));
        assert_eq!(draft.build(Some(&item), "GitHub", read).unwrap(), item);
    }

    #[test]
    fn switching_type_keeps_every_value() {
        let mut draft = Draft::new_item(PersonalSecretKind::Login, fake);
        set(&mut draft, "username", "alice");
        set(&mut draft, "password", "hunter2");
        set(&mut draft, "notes", "remember");
        let custom = draft.insert_custom(PersonalFieldType::Concealed, fake);
        draft
            .sections
            .iter_mut()
            .flat_map(|section| &mut section.rows)
            .find(|row| row.key == custom)
            .unwrap()
            .inputs = ("42".into(), Some("Answer".into()));
        let switched = draft.switched(PersonalSecretKind::ApiCredential, &values(&draft), fake);
        let item = switched.build(None, "API", read).unwrap();
        let fields: Vec<_> = item
            .sections
            .iter()
            .flat_map(|section| &section.fields)
            .filter(|field| field.text().is_some_and(|text| !text.is_empty()))
            .map(|field| {
                (
                    field.id.as_str(),
                    field.label.as_str(),
                    field.text().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            fields,
            [
                ("username", "Username", "alice"),
                ("custom-0", "Password", "hunter2"),
                ("custom-1", "Answer", "42"),
            ]
        );
        assert_eq!(item.notes.as_deref(), Some("remember"));
        assert_eq!(item.kind, PersonalSecretKind::ApiCredential);
    }

    #[test]
    fn structured_values_must_stay_valid_json() {
        let mut item = login();
        item.sections[0].fields.push(PersonalField::new(
            "address",
            "Address",
            PersonalFieldType::Address,
            serde_json::json!({"city": "Kyiv"}),
        ));
        let mut draft = Draft::from_item(&item, fake);
        let key = set(&mut draft, "address", "{ broken");
        assert_eq!(
            draft.build(Some(&item), "GitHub", read).unwrap_err(),
            Problem::new(Target::Row(key), INVALID_JSON)
        );
        set(&mut draft, "address", r#"{"city": "Lviv"}"#);
        let built = draft.build(Some(&item), "GitHub", read).unwrap();
        assert_eq!(
            built.sections[0].fields[4].value,
            serde_json::json!({"city": "Lviv"})
        );
    }

    #[test]
    fn custom_fields_start_with_the_picked_type_and_can_change_it() {
        let item = login();
        let mut draft = Draft::from_item(&item, fake);
        let custom = draft.insert_custom(PersonalFieldType::Email, fake);
        let row = draft.row(custom).unwrap();
        assert_eq!(row.field_type, PersonalFieldType::Email);
        assert!(!row.concealed);
        let username = draft.key_at(0).unwrap();
        assert!(!draft.set_field_type(username, PersonalFieldType::Concealed));
        assert!(draft.set_field_type(custom, PersonalFieldType::Concealed));
        assert!(draft.row(custom).unwrap().concealed);
    }

    #[test]
    fn unreadable_values_stop_the_save() {
        let item = login();
        let mut draft = Draft::from_item(&item, fake);
        let password = set(&mut draft, "password", UNREADABLE);
        assert_eq!(
            draft.build(Some(&item), "GitHub", read).unwrap_err(),
            Problem::new(Target::Row(password), ALLOCATION_FAILED)
        );
    }

    #[test]
    fn salvaged_items_keep_every_readable_change() {
        let mut item = login();
        item.sections[0].fields.push(PersonalField::new(
            "address",
            "Address",
            PersonalFieldType::Address,
            serde_json::json!({"city": "Kyiv"}),
        ));
        let mut draft = Draft::from_item(&item, fake);
        set(&mut draft, "username", "bob");
        set(&mut draft, "password", UNREADABLE);
        set(&mut draft, "address", "{ broken");
        let saved = draft.salvage(Some(&item), " ", read).unwrap();
        assert_eq!(saved.title, "GitHub");
        assert_eq!(saved.username(), Some("bob"));
        assert_eq!(saved.sections[0].fields[1].value, "hunter2");
        assert_eq!(
            saved.sections[0].fields[4].value,
            serde_json::json!({"city": "Kyiv"})
        );
    }

    #[test]
    fn salvaged_new_items_are_named_after_their_type() {
        let mut draft = Draft::new_item(PersonalSecretKind::Login, fake);
        assert_eq!(
            draft.salvage(None, "", read).unwrap_err(),
            Problem::new(Target::Item, NOTHING_ENTERED)
        );
        set(&mut draft, "password", "hunter2");
        let saved = draft.salvage(None, "", read).unwrap();
        assert_eq!(saved.title, PersonalSecretKind::Login.label());
        assert_eq!(saved.sections[0].fields[1].value, "hunter2");
    }

    #[test]
    fn open_edits_keep_the_vault_unsealed_or_save_before_it_seals() {
        let now = 1_000;
        let far = (now + 300, now + 3_600);
        let idle_soon = (now + 10, now + 3_600);
        let hard_stop = (now + 10, now + 10);
        let recent = Duration::from_secs(1);
        let stale = TOUCH_EVERY;
        assert_eq!(guard(now, far, false, stale, true), Guard::Wait);
        assert_eq!(guard(now, far, true, recent, true), Guard::Wait);
        assert_eq!(guard(now, far, true, stale, false), Guard::Touch);
        assert_eq!(guard(now, idle_soon, true, recent, true), Guard::Touch);
        assert_eq!(guard(now, idle_soon, false, recent, true), Guard::Save);
        assert_eq!(guard(now, idle_soon, false, recent, false), Guard::Wait);
        assert_eq!(guard(now, hard_stop, true, recent, true), Guard::Save);
    }
}

use std::collections::HashMap;

use zeroize::Zeroizing;

use super::{ImportChange, personal};
use crate::personal::{PersonalField, PersonalSecret, PersonalSection};
use crate::{VaultArchiveEntry, WireSecret};

#[derive(Debug)]
pub struct ImportValue {
    pub value: Option<WireSecret>,
    pub concealed: bool,
    pub filled: bool,
    pub context: Option<String>,
}

impl ImportValue {
    fn text(text: Option<&str>, concealed: bool, reveal: bool) -> anyhow::Result<Self> {
        let text = text.filter(|text| !text.is_empty());
        Ok(Self {
            value: text
                .filter(|_| !concealed || reveal)
                .map(|text| WireSecret::new(text.as_bytes().to_vec()))
                .transpose()?,
            concealed,
            filled: text.is_some(),
            context: None,
        })
    }

    fn json(
        value: Option<&serde_json::Value>,
        concealed: bool,
        reveal: bool,
    ) -> anyhow::Result<Self> {
        match value {
            None | Some(serde_json::Value::Null) => Self::text(None, concealed, reveal),
            Some(serde_json::Value::String(text)) => Self::text(Some(text), concealed, reveal),
            Some(value) => Ok(Self {
                value: if !concealed || reveal {
                    Some(WireSecret::new(serde_json::to_vec_pretty(value)?)?)
                } else {
                    None
                },
                concealed,
                filled: true,
                context: None,
            }),
        }
    }
}

#[derive(Debug)]
pub struct ImportComparison {
    pub change: ImportChange,
    pub section: Option<String>,
    pub current: ImportValue,
    pub incoming: ImportValue,
}

fn text_change(
    rows: &mut Vec<ImportComparison>,
    revealed: &[usize],
    change: ImportChange,
    current: Option<&str>,
    incoming: Option<&str>,
    concealed: bool,
) -> anyhow::Result<()> {
    if current != incoming {
        text_row(rows, revealed, change, current, incoming, concealed)?;
    }
    Ok(())
}

fn text_row(
    rows: &mut Vec<ImportComparison>,
    revealed: &[usize],
    change: ImportChange,
    current: Option<&str>,
    incoming: Option<&str>,
    concealed: bool,
) -> anyhow::Result<()> {
    let reveal = revealed.contains(&rows.len());
    rows.push(ImportComparison {
        change,
        section: None,
        current: ImportValue::text(current, concealed, reveal)?,
        incoming: ImportValue::text(incoming, concealed, reveal)?,
    });
    Ok(())
}

fn field_change(
    rows: &mut Vec<ImportComparison>,
    revealed: &[usize],
    current: Option<(&PersonalSection, &PersonalField)>,
    incoming: Option<(&PersonalSection, &PersonalField)>,
) -> anyhow::Result<()> {
    if current.map(|(section, field)| (&section.label, field))
        == incoming.map(|(section, field)| (&section.label, field))
    {
        return Ok(());
    }
    let (section, field) = incoming.or(current).unwrap();
    let concealed = current.is_some_and(|(_, field)| field.is_concealed())
        || incoming.is_some_and(|(_, field)| field.is_concealed());
    let reveal = revealed.contains(&rows.len());
    let mut before = ImportValue::json(current.map(|(_, field)| &field.value), concealed, reveal)?;
    let mut after = ImportValue::json(incoming.map(|(_, field)| &field.value), concealed, reveal)?;
    let context = |value: Option<(&PersonalSection, &PersonalField)>| {
        value.map(|(section, field)| {
            [
                section.label.as_str(),
                field.label.as_str(),
                field.field_type.label(),
                if field.is_concealed() { "Hidden" } else { "" },
            ]
            .into_iter()
            .filter(|label| !label.is_empty())
            .collect::<Vec<_>>()
            .join(" · ")
        })
    };
    if context(current) != context(incoming) {
        before.context = context(current);
        after.context = context(incoming);
    }
    rows.push(ImportComparison {
        change: ImportChange::Field(field.label.clone()),
        section: (!section.label.is_empty()).then(|| section.label.clone()),
        current: before,
        incoming: after,
    });
    Ok(())
}

pub(super) fn comparisons(
    incoming: &VaultArchiveEntry,
    stored: &VaultArchiveEntry,
    revealed: &[usize],
) -> anyhow::Result<Vec<ImportComparison>> {
    let mut rows = Vec::new();
    if incoming.value.expose() == stored.value.expose() && incoming.evict_at == stored.evict_at {
        return Ok(rows);
    }
    let (Some(new), Some(old)) = (personal(incoming)?, personal(stored)?) else {
        if incoming.value.expose() != stored.value.expose() {
            let before = Zeroizing::new(
                String::from_utf8(stored.value.expose().to_vec())
                    .unwrap_or_else(|error| hex::encode(&*Zeroizing::new(error.into_bytes()))),
            );
            let after = Zeroizing::new(
                String::from_utf8(incoming.value.expose().to_vec())
                    .unwrap_or_else(|error| hex::encode(&*Zeroizing::new(error.into_bytes()))),
            );
            text_row(
                &mut rows,
                revealed,
                ImportChange::OtherFields,
                Some(&before),
                Some(&after),
                true,
            )?;
        }
        text_change(
            &mut rows,
            revealed,
            ImportChange::OtherFields,
            stored.evict_at.map(|value| value.to_string()).as_deref(),
            incoming.evict_at.map(|value| value.to_string()).as_deref(),
            false,
        )?;
        return Ok(rows);
    };
    metadata_changes(&mut rows, revealed, &old, &new)?;
    field_changes(&mut rows, revealed, &old, &new)?;
    text_change(
        &mut rows,
        revealed,
        ImportChange::OtherFields,
        stored.evict_at.map(|value| value.to_string()).as_deref(),
        incoming.evict_at.map(|value| value.to_string()).as_deref(),
        false,
    )?;
    if old.source != new.source {
        let reveal = revealed.contains(&rows.len());
        rows.push(ImportComparison {
            change: ImportChange::Source,
            section: None,
            current: ImportValue::json(old.source.as_ref(), true, reveal)?,
            incoming: ImportValue::json(new.source.as_ref(), true, reveal)?,
        });
    }
    Ok(rows)
}

fn metadata_changes(
    rows: &mut Vec<ImportComparison>,
    revealed: &[usize],
    old: &PersonalSecret,
    new: &PersonalSecret,
) -> anyhow::Result<()> {
    for (change, before, after, concealed) in [
        (
            ImportChange::Title,
            Some(old.title.as_str()),
            Some(new.title.as_str()),
            false,
        ),
        (
            ImportChange::Kind,
            Some(old.kind.label()),
            Some(new.kind.label()),
            false,
        ),
        (
            ImportChange::Notes,
            old.notes.as_deref(),
            new.notes.as_deref(),
            true,
        ),
        (
            ImportChange::Folder,
            old.folder.as_deref(),
            new.folder.as_deref(),
            false,
        ),
        (
            ImportChange::Favorite,
            Some(if old.favorite { "true" } else { "false" }),
            Some(if new.favorite { "true" } else { "false" }),
            false,
        ),
        (
            ImportChange::Archived,
            Some(if old.archived { "true" } else { "false" }),
            Some(if new.archived { "true" } else { "false" }),
            false,
        ),
    ] {
        text_change(rows, revealed, change, before, after, concealed)?;
    }
    if old.tags != new.tags {
        let before = Zeroizing::new(serde_json::to_string(&old.tags)?);
        let after = Zeroizing::new(serde_json::to_string(&new.tags)?);
        text_change(
            rows,
            revealed,
            ImportChange::Tags,
            Some(&before),
            Some(&after),
            false,
        )?;
    }
    Ok(())
}

fn field_changes(
    rows: &mut Vec<ImportComparison>,
    revealed: &[usize],
    old: &PersonalSecret,
    new: &PersonalSecret,
) -> anyhow::Result<()> {
    let old_fields: HashMap<_, _> = old
        .sections
        .iter()
        .flat_map(|section| {
            section
                .fields
                .iter()
                .map(move |field| ((section.id.as_str(), field.id.as_str()), (section, field)))
        })
        .collect();
    let new_fields: HashMap<_, _> = new
        .sections
        .iter()
        .flat_map(|section| {
            section
                .fields
                .iter()
                .map(move |field| ((section.id.as_str(), field.id.as_str()), (section, field)))
        })
        .collect();
    for section in &new.sections {
        for field in &section.fields {
            field_change(
                rows,
                revealed,
                old_fields
                    .get(&(section.id.as_str(), field.id.as_str()))
                    .copied(),
                Some((section, field)),
            )?;
        }
    }
    for section in &old.sections {
        for field in &section.fields {
            if !new_fields.contains_key(&(section.id.as_str(), field.id.as_str())) {
                field_change(rows, revealed, Some((section, field)), None)?;
            }
        }
    }
    let before_sections = old
        .sections
        .iter()
        .map(|section| {
            (
                &section.label,
                section
                    .fields
                    .iter()
                    .map(|field| &field.label)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let after_sections = new
        .sections
        .iter()
        .map(|section| {
            (
                &section.label,
                section
                    .fields
                    .iter()
                    .map(|field| &field.label)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Vec<_>>();
    let section_labels_changed = old
        .sections
        .iter()
        .map(|section| &section.label)
        .ne(new.sections.iter().map(|section| &section.label));
    let field_order_changed = old_fields.len() == new_fields.len()
        && old_fields.keys().all(|key| new_fields.contains_key(key))
        && old
            .sections
            .iter()
            .flat_map(|section| section.fields.iter().map(|field| (&section.id, &field.id)))
            .ne(new
                .sections
                .iter()
                .flat_map(|section| section.fields.iter().map(|field| (&section.id, &field.id))));
    if section_labels_changed || field_order_changed {
        text_row(
            rows,
            revealed,
            ImportChange::OtherFields,
            Some(&Zeroizing::new(serde_json::to_string_pretty(
                &before_sections,
            )?)),
            Some(&Zeroizing::new(serde_json::to_string_pretty(
                &after_sections,
            )?)),
            false,
        )?;
    }
    Ok(())
}

use crate::api::{Draft, ErrorCode, Field, FieldType, Item, Kind, Section, Summary};
use crate::core::{Failure, Outcome};
use factorseal::DocumentKind;
use factorseal::personal::{
    PERSONAL_SECRET_NAMESPACE, PersonalField, PersonalFieldType, PersonalSecret,
    PersonalSecretKind, PersonalSection, website, zeroize_json_strings,
};
use factorseal::vault::VaultEntryMetadata;
use std::collections::HashMap;
use zeroize::Zeroizing;

const NOTES: &str = "notes";
const NOTES_LABEL: &str = "Notes";

pub(crate) fn kind_to_core(kind: Kind) -> PersonalSecretKind {
    match kind {
        Kind::Login => PersonalSecretKind::Login,
        Kind::SecureNote => PersonalSecretKind::SecureNote,
        Kind::Card => PersonalSecretKind::Card,
        Kind::Identity => PersonalSecretKind::Identity,
        Kind::SshKey => PersonalSecretKind::SshKey,
        Kind::ApiCredential => PersonalSecretKind::ApiCredential,
        Kind::Passport => PersonalSecretKind::Passport,
        Kind::BankAccount => PersonalSecretKind::BankAccount,
        Kind::Document => PersonalSecretKind::Document,
        Kind::Generic => PersonalSecretKind::Generic,
    }
}

fn kind_from_core(kind: PersonalSecretKind) -> Kind {
    match kind {
        PersonalSecretKind::Login => Kind::Login,
        PersonalSecretKind::SecureNote => Kind::SecureNote,
        PersonalSecretKind::Card => Kind::Card,
        PersonalSecretKind::Identity => Kind::Identity,
        PersonalSecretKind::SshKey => Kind::SshKey,
        PersonalSecretKind::ApiCredential => Kind::ApiCredential,
        PersonalSecretKind::Passport => Kind::Passport,
        PersonalSecretKind::BankAccount => Kind::BankAccount,
        PersonalSecretKind::Document => Kind::Document,
        PersonalSecretKind::Generic => Kind::Generic,
    }
}

fn field_type(field_type: &PersonalFieldType) -> FieldType {
    match field_type {
        PersonalFieldType::Text => FieldType::Text,
        PersonalFieldType::Concealed => FieldType::Concealed,
        PersonalFieldType::Url => FieldType::Url,
        PersonalFieldType::Email => FieldType::Email,
        PersonalFieldType::Phone => FieldType::Phone,
        PersonalFieldType::Date => FieldType::Date,
        PersonalFieldType::MonthYear => FieldType::MonthYear,
        PersonalFieldType::Totp => FieldType::Totp,
        PersonalFieldType::Multiline => FieldType::Multiline,
        PersonalFieldType::Boolean => FieldType::Boolean,
        PersonalFieldType::CardNumber => FieldType::CardNumber,
        PersonalFieldType::SshKey => FieldType::SshKey,
        PersonalFieldType::Address => FieldType::Address,
        PersonalFieldType::Reference => FieldType::Reference,
        PersonalFieldType::Unknown(_) => FieldType::Unknown,
    }
}

fn core_field_type(field_type: &FieldType) -> Option<PersonalFieldType> {
    Some(match field_type {
        FieldType::Text => PersonalFieldType::Text,
        FieldType::Concealed => PersonalFieldType::Concealed,
        FieldType::Url => PersonalFieldType::Url,
        FieldType::Email => PersonalFieldType::Email,
        FieldType::Phone => PersonalFieldType::Phone,
        FieldType::Date => PersonalFieldType::Date,
        FieldType::MonthYear => PersonalFieldType::MonthYear,
        FieldType::Totp => PersonalFieldType::Totp,
        FieldType::Multiline => PersonalFieldType::Multiline,
        FieldType::Boolean => PersonalFieldType::Boolean,
        FieldType::CardNumber => PersonalFieldType::CardNumber,
        FieldType::SshKey => PersonalFieldType::SshKey,
        FieldType::Address => PersonalFieldType::Address,
        FieldType::Reference => PersonalFieldType::Reference,
        FieldType::Unknown => return None,
    })
}

pub(crate) fn summaries(entries: Vec<VaultEntryMetadata>) -> Vec<Summary> {
    let mut items: Vec<Summary> = entries
        .into_iter()
        .filter(|entry| {
            entry.document_kind == DocumentKind::LocalKeyring
                && entry.partition == PERSONAL_SECRET_NAMESPACE
        })
        .filter_map(|entry| {
            let (id, None) = entry.address.as_local()? else {
                return None;
            };
            let kind = entry
                .display_type
                .as_deref()
                .and_then(|label| {
                    PersonalSecretKind::ALL
                        .into_iter()
                        .find(|kind| kind.label() == label)
                })
                .unwrap_or_default();
            Some(Summary {
                id: id.to_owned(),
                title: entry.display_name.clone().unwrap_or_default(),
                kind: kind_from_core(kind),
                username: entry.display_username.clone(),
                website: entry.display_website.clone(),
                updated_at: entry.updated_at,
                favorite: entry.favorite,
            })
        })
        .collect();
    items.sort_by(|a, b| {
        b.favorite
            .cmp(&a.favorite)
            .then_with(|| a.title.to_lowercase().cmp(&b.title.to_lowercase()))
            .then_with(|| a.id.cmp(&b.id))
    });
    items
}

pub(crate) fn view(item: &PersonalSecret, version: Option<&[u8; 32]>, values: bool) -> Item {
    Item {
        id: item.id.clone(),
        kind: kind_from_core(item.kind),
        title: item.title.clone(),
        favorite: item.favorite,
        notes: item.notes.clone().filter(|_| values),
        notes_filled: item.notes.as_ref().is_some_and(|notes| !notes.is_empty()),
        website: item.website_host(),
        sections: item
            .sections
            .iter()
            .map(|section| Section {
                id: section.id.clone(),
                label: section.label.clone(),
                fields: section
                    .fields
                    .iter()
                    .map(|field| {
                        let filled = !is_empty(&field.value);
                        let shown = values || !field.is_concealed();
                        Field {
                            id: field.id.clone(),
                            label: field.label.clone(),
                            kind: field_type(&field.field_type),
                            concealed: field.is_concealed(),
                            filled,
                            value: shown.then(|| field.value.clone()),
                            link: (shown && field.field_type == PersonalFieldType::Url)
                                .then(|| field.text().and_then(website::url))
                                .flatten(),
                        }
                    })
                    .collect(),
            })
            .collect(),
        version: version.map(hex::encode),
    }
}

pub(crate) fn draft(item: &PersonalSecret, version: Option<&[u8; 32]>) -> Item {
    let mut draft = view(item, version, true);
    if !draft.sections.iter().any(|section| section.id == NOTES) {
        let notes = item.notes.clone().unwrap_or_default();
        draft.sections.push(Section {
            id: NOTES.to_owned(),
            label: NOTES_LABEL.to_owned(),
            fields: vec![Field {
                id: NOTES.to_owned(),
                label: NOTES_LABEL.to_owned(),
                kind: FieldType::Multiline,
                concealed: true,
                filled: !notes.is_empty(),
                value: Some(serde_json::Value::String(notes)),
                link: None,
            }],
        });
    }
    draft
}

fn is_notes(section: &PersonalSection) -> bool {
    section.id == NOTES
        && section
            .fields
            .iter()
            .all(|field| field.id == NOTES && field.field_type == PersonalFieldType::Multiline)
}

fn is_empty(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null => true,
        serde_json::Value::String(text) => text.is_empty(),
        _ => false,
    }
}

pub(crate) fn reveal(
    item: &PersonalSecret,
    section: &str,
    field: &str,
) -> Option<Zeroizing<String>> {
    let Some(found) = item
        .sections
        .iter()
        .find(|candidate| candidate.id == section)
    else {
        return (section == NOTES && field == NOTES)
            .then_some(item.notes.as_deref())
            .flatten()
            .filter(|notes| !notes.is_empty())
            .map(|notes| Zeroizing::new(notes.to_owned()));
    };
    found
        .fields
        .iter()
        .find(|candidate| candidate.id == field)
        .and_then(|field| match &field.value {
            serde_json::Value::String(text) if !text.is_empty() => {
                Some(Zeroizing::new(text.clone()))
            }
            serde_json::Value::Null | serde_json::Value::String(_) => None,
            other => Some(Zeroizing::new(other.to_string())),
        })
}

pub(crate) fn apply(draft: &Draft, current: Option<PersonalSecret>) -> Outcome<PersonalSecret> {
    if draft.id.is_empty() {
        return Err(Failure::new(ErrorCode::Invalid, "the item has no ID"));
    }
    let mut item = if let Some(item) = current {
        if item.id != draft.id {
            return Err(Failure::new(ErrorCode::Invalid, "the item ID changed"));
        }
        item
    } else {
        let mut item = PersonalSecret::new(kind_to_core(draft.kind), String::new());
        item.id.clone_from(&draft.id);
        item
    };
    let previous: HashMap<(String, String), PersonalFieldType> = item
        .sections
        .iter()
        .flat_map(|section| {
            section.fields.iter().map(|field| {
                (
                    (section.id.clone(), field.id.clone()),
                    field.field_type.clone(),
                )
            })
        })
        .collect();
    item.kind = kind_to_core(draft.kind);
    draft.title.trim().clone_into(&mut item.title);
    item.favorite = draft.favorite;
    item.notes.clone_from(&draft.notes);
    let mut sections = Vec::with_capacity(draft.sections.len());
    for section in &draft.sections {
        let mut fields = Vec::with_capacity(section.fields.len());
        for field in &section.fields {
            let kind = match core_field_type(&field.kind) {
                Some(kind) => kind,
                None => previous
                    .get(&(section.id.clone(), field.id.clone()))
                    .cloned()
                    .ok_or_else(|| {
                        Failure::new(ErrorCode::Invalid, "an imported field has no original type")
                    })?,
            };
            let value = field
                .value
                .clone()
                .unwrap_or(serde_json::Value::String(String::new()));
            let mut stored = PersonalField::new(field.id.clone(), field.label.clone(), kind, value);
            stored.concealed = stored.field_type.concealed() || field.concealed;
            if stored.field_type == PersonalFieldType::Totp
                && let Some(text) = stored.text()
            {
                let normalized = factorseal::personal::totp::stored(text).ok_or_else(|| {
                    Failure::new(
                        ErrorCode::Invalid,
                        "a one-time password setup key is not valid",
                    )
                })?;
                zeroize_json_strings(&mut stored.value);
                stored.value = serde_json::Value::String(normalized.to_string());
            }
            fields.push(stored);
        }
        sections.push(PersonalSection {
            id: section.id.clone(),
            label: section.label.clone(),
            fields,
        });
    }
    if let Some(notes) = sections.iter().find(|section| is_notes(section)) {
        item.notes = notes
            .fields
            .first()
            .and_then(PersonalField::text)
            .filter(|text| !text.is_empty())
            .map(str::to_owned);
    }
    sections.retain(|section| !is_notes(section));
    item.sections = sections;
    item.encode()
        .map_err(|error| Failure::new(ErrorCode::Invalid, error.to_string()))?;
    Ok(item)
}

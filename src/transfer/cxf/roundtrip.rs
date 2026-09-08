//! Preserve source structure while applying current Personal field values.

use std::collections::{HashMap, HashSet};

use anyhow::bail;
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Serialize, Deserialize)]
pub(super) struct Binding {
    section: String,
    field: String,
    path: String,
    kind: BindingKind,
}

#[derive(Serialize, Deserialize)]
enum BindingKind {
    Field,
    Value,
    Totp,
    Opaque,
    Note,
}

impl Binding {
    pub(super) fn field(
        value: &Value,
        section: &str,
        field: &str,
        path: String,
    ) -> anyhow::Result<Self> {
        let meta = extension(value, FIELD_EXTENSION)?;
        Ok(Self {
            section: meta
                .map(|m| text(m, "sectionId"))
                .transpose()?
                .unwrap_or(section)
                .into(),
            field: meta
                .map(|m| text(m, "id"))
                .transpose()?
                .unwrap_or(field)
                .into(),
            path,
            kind: BindingKind::Field,
        })
    }
    pub(super) fn value(section: &str, field: &str, path: String) -> Self {
        Self {
            section: section.into(),
            field: field.into(),
            path,
            kind: BindingKind::Value,
        }
    }
    pub(super) fn note(index: usize) -> Self {
        Self {
            section: String::new(),
            field: String::new(),
            path: format!("/credentials/{index}"),
            kind: BindingKind::Note,
        }
    }
    pub(super) fn totp(meta: Option<&Value>, section: &str, index: usize) -> anyhow::Result<Self> {
        let mut binding = Self::field(
            meta.unwrap_or(&Value::Null),
            section,
            "totp",
            format!("/credentials/{index}"),
        )?;
        binding.kind = BindingKind::Totp;
        Ok(binding)
    }
    pub(super) fn opaque(section: &str, field: &str, index: usize) -> Self {
        Self {
            section: section.into(),
            field: field.into(),
            path: format!("/credentials/{index}"),
            kind: BindingKind::Opaque,
        }
    }
}

pub(super) fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

pub(super) fn export(secrets: &[PersonalSecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if secrets.iter().all(|item| item.source.is_none()) {
        return export_native_json(secrets);
    }
    if secrets.len() > MAX_MANAGER_ITEMS {
        bail!("too many CXF items");
    }
    let mut root = SensitiveJson(serde_json::from_slice(&export_native_json(&[])?)?);
    let native_account = root.0["accounts"][0].take();
    root.0["accounts"] = json!([]);
    let mut accounts: Vec<SensitiveJson> = Vec::new();
    let mut origins: HashMap<String, usize> = HashMap::new();
    let mut item_ids = HashSet::new();
    let mut account_ids = HashSet::new();
    let mut source_ids = HashSet::new();
    for (index, item) in secrets.iter().enumerate() {
        item.encode()?;
        if !item_ids.insert(&item.id) {
            bail!("duplicate personal-item ID in CXF export");
        }
        let (origin, account, encoded) = if let Some(source) = &item.source {
            if source["format"] != "cxf" {
                bail!(
                    "CXF item {} has metadata from another format; use a FactorSeal archive",
                    index + 1
                );
            }
            let account = source
                .get("account")
                .cloned()
                .unwrap_or_else(|| native_account.clone());
            let origin = format!(
                "{}:{}",
                source["header"]["exporterRpId"].as_str().unwrap_or(""),
                text(&account, "id")?
            );
            if let Some(header) = source.get("header") {
                for (key, value) in header.as_object().context("invalid CXF source header")? {
                    if [
                        "version",
                        "exporterRpId",
                        "exporterDisplayName",
                        "timestamp",
                        "accounts",
                    ]
                    .contains(&key.as_str())
                    {
                        continue;
                    }
                    if let Some(existing) = root.0.get(key) {
                        if existing != value {
                            bail!("conflicting CXF source header metadata");
                        }
                    } else {
                        root.0[key] = value.clone();
                    }
                }
            }
            (
                origin,
                account,
                merge_item(item, &source["item"], &valid_id(&source["account"], "id")?)
                    .map_err(|e| anyhow::anyhow!("cannot export CXF item {}: {e}", index + 1))?,
            )
        } else {
            (String::new(), native_account.clone(), export_item(item)?)
        };
        let account_index = if let Some(existing) = origins.get(&origin) {
            if without(&accounts[*existing], "items")? != without(&account, "items")? {
                bail!("conflicting CXF account metadata; export the source accounts separately");
            }
            *existing
        } else {
            let id = valid_id(&account, "id")?;
            if !account_ids.insert(id) {
                bail!("CXF source accounts have colliding IDs; export them separately");
            }
            let index = accounts.len();
            let mut account = SensitiveJson(account);
            account.0["items"] = json!([]);
            accounts.push(account);
            origins.insert(origin, index);
            index
        };
        let items = accounts[account_index].0["items"]
            .as_array_mut()
            .context("invalid CXF account")?;
        let id = valid_id(&encoded, "id")?;
        if !source_ids.insert((account_index, id)) {
            bail!("duplicate CXF source item ID");
        }
        items.push(encoded);
    }
    root.0["accounts"] = accounts.iter_mut().map(|a| a.0.take()).collect();
    let encoded = Zeroizing::new(serde_json::to_vec_pretty(&root.0)?);
    if encoded.len() > MAX_MANAGER_FILE_BYTES {
        bail!("CXF payload is larger than 128 MiB");
    }
    Ok(encoded)
}

fn field_map(item: &PersonalSecret) -> HashMap<(&str, &str), (&PersonalSection, &PersonalField)> {
    item.sections
        .iter()
        .flat_map(|section| {
            section
                .fields
                .iter()
                .map(move |field| ((section.id.as_str(), field.id.as_str()), (section, field)))
        })
        .collect()
}

#[allow(clippy::too_many_lines)]
fn merge_item(
    current: &PersonalSecret,
    original: &Value,
    account_id: &[u8],
) -> anyhow::Result<Value> {
    // Re-derive bindings from the validated source, never trust stored JSON pointers.
    let (baseline, bindings) = import_item(original, account_id, &valid_id(original, "id")?)?;
    if baseline.id != current.id {
        bail!("CXF source identity changed; cannot preserve references");
    }
    let current_fields = field_map(current);
    let baseline_fields = field_map(&baseline);
    let mut consumed = HashSet::new();
    let mut result = SensitiveJson(original.clone());
    result.0["title"] = current.title.clone().into();
    result.0["favorite"] = current.favorite.into();
    result.0["tags"] = json!(current.tags);
    let mut notes_written = false;
    for binding in &bindings {
        if matches!(binding.kind, BindingKind::Note) {
            notes_written = true;
            if let Some(notes) = &current.notes {
                let note = result
                    .0
                    .pointer_mut(&binding.path)
                    .context("invalid CXF note binding")?;
                note["content"]["value"] = notes.clone().into();
            } else {
                remove(&mut result.0, &binding.path)?;
            }
            continue;
        }
        let key = (binding.section.as_str(), binding.field.as_str());
        // Carry scope-only URLs as typed custom fields too, retaining their
        // labels and identities when scope array indices change.
        if !binding.path.starts_with("/scope/") {
            consumed.insert(key);
        }
        let Some((section, field)) = current_fields.get(&key) else {
            remove(&mut result.0, &binding.path)?;
            continue;
        };
        let target = result
            .0
            .pointer_mut(&binding.path)
            .context("invalid CXF field binding")?;
        match binding.kind {
            BindingKind::Field => {
                let (_, old) = baseline_fields
                    .get(&key)
                    .context("invalid CXF source field")?;
                merge_field(target, field, old, section, &current.id)?;
            }
            BindingKind::Value => {
                *target = field
                    .text()
                    .context("CXF source value must remain text")?
                    .into();
            }
            BindingKind::Totp => {
                let encoded =
                    SensitiveJson(totp::export(field.text().context("TOTP must be text")?)?);
                for key in [
                    "secret",
                    "period",
                    "digits",
                    "algorithm",
                    "username",
                    "issuer",
                ] {
                    target
                        .as_object_mut()
                        .context("invalid source TOTP")?
                        .remove(key);
                    if let Some(value) = encoded.get(key) {
                        target[key] = value.clone();
                    }
                }
            }
            BindingKind::Opaque => {
                if field.value != baseline_fields[&key].1.value {
                    bail!("unsupported credentials cannot be edited as raw fields");
                }
                *target = field.value.clone();
            }
            BindingKind::Note => unreachable!(),
        }
    }
    let credentials = result.0["credentials"]
        .as_array_mut()
        .context("invalid CXF credentials")?;
    for credential in &mut *credentials {
        if let Some(fields) = credential.get_mut("fields").and_then(Value::as_array_mut) {
            fields.retain(|f| !f.is_null());
        }
    }
    // Array indices remain stable until all bindings have been applied.
    let surviving: Vec<_> = credentials
        .iter()
        .enumerate()
        .filter(|(_, c)| !c.is_null())
        .map(|(i, _)| i)
        .collect();
    credentials.retain(|c| !c.is_null());
    let mut new_totp_fields = Vec::new();
    for section in &current.sections {
        let mut fields = Vec::new();
        for field in &section.fields {
            if consumed.contains(&(section.id.as_str(), field.id.as_str())) {
                continue;
            }
            if field.field_type == PersonalFieldType::Totp
                && field.text().is_some_and(|value| !value.is_empty())
            {
                let encoded = SensitiveJson(export_field(field, section, &current.id)?);
                new_totp_fields
                    .push(json!({"index":credentials.len(),"field":without(&encoded,"value")?}));
                credentials.push(totp::export(field.text().context("invalid TOTP value")?)?);
                continue;
            }
            fields.push(export_field(field, section, &current.id)?);
        }
        if !fields.is_empty() {
            credentials.push(json!({"type":"custom-fields","id":identifier(&current.id, &section.id),"label":section.label,"fields":fields}));
        }
    }
    if !notes_written && let Some(notes) = &current.notes {
        credentials.push(json!({"type":"note","content":{"fieldType":"string","value":notes}}));
    }
    if let Some(urls) = result
        .0
        .pointer_mut("/scope/urls")
        .and_then(Value::as_array_mut)
    {
        urls.retain(|url| !url.is_null());
    }
    let urls: Vec<_> = current
        .sections
        .iter()
        .flat_map(|s| &s.fields)
        .filter(|f| f.field_type == PersonalFieldType::Url)
        .filter_map(PersonalField::text)
        .filter(|url| !url.is_empty())
        .collect();
    if !urls.is_empty() || result.0.get("scope").is_some() {
        if result.0.get("scope").is_none() {
            result.0["scope"] = json!({"androidApps":[]});
        }
        result.0["scope"]["urls"] = json!(urls);
    }
    if extension(&result, ITEM_EXTENSION)?.is_none() {
        if result.0.get("extensions").is_none() {
            result.0["extensions"] = json!([]);
        }
        result.0["extensions"]
            .as_array_mut()
            .context("invalid CXF extensions")?
            .push(json!({
                "name":ITEM_EXTENSION,"version":2,"id":current.id
            }));
    }
    if let Some(extensions) = result.0.get_mut("extensions").and_then(Value::as_array_mut)
        && let Some(meta) = extensions.iter_mut().find(|e| e["name"] == ITEM_EXTENSION)
    {
        if meta["id"] != current.id {
            bail!("CXF source identity changed; cannot preserve references");
        }
        meta["kind"] = json!(current.kind);
        meta["archived"] = current.archived.into();
        meta["folder"] = json!(current.folder);
        meta["sections"] = current.sections.iter().map(|s| json!({"id":s.id,"label":s.label,"fields":s.fields.iter().map(|f| &f.id).collect::<Vec<_>>()})).collect();
        let mut opaque_fields = Vec::new();
        for binding in bindings
            .iter()
            .filter(|binding| matches!(binding.kind, BindingKind::Opaque))
        {
            let key = (binding.section.as_str(), binding.field.as_str());
            let Some((section, field)) = current_fields.get(&key) else {
                continue;
            };
            let original_index: usize = binding
                .path
                .rsplit('/')
                .next()
                .context("invalid opaque binding")?
                .parse()?;
            let index = surviving
                .iter()
                .position(|old| *old == original_index)
                .context("missing opaque credential")?;
            opaque_fields.push(json!({"index":index,"sectionId":section.id,"sectionLabel":section.label,"id":field.id,"label":field.label}));
        }
        if !opaque_fields.is_empty() || meta.get("opaqueFields").is_some() {
            meta["opaqueFields"] = opaque_fields.into();
        }
        if let Some(fields) = meta.get_mut("totpFields").and_then(Value::as_array_mut) {
            fields.retain_mut(|field| {
                if let Some(index) = field["index"]
                    .as_u64()
                    .and_then(|i| usize::try_from(i).ok())
                    .and_then(|i| surviving.iter().position(|old| *old == i))
                {
                    field["index"] = index.into();
                    true
                } else {
                    false
                }
            });
            fields.extend(new_totp_fields);
        } else if !new_totp_fields.is_empty() {
            meta["totpFields"] = new_totp_fields.into();
        }
        // Refresh metadata for every surviving TOTP, including foreign items.
        // The native projection must follow edits and shifted credential indices.
        for binding in bindings
            .iter()
            .filter(|binding| matches!(binding.kind, BindingKind::Totp))
        {
            let key = (binding.section.as_str(), binding.field.as_str());
            let Some((section, field)) = current_fields.get(&key) else {
                continue;
            };
            let original_index: usize = binding
                .path
                .rsplit('/')
                .next()
                .context("invalid TOTP binding")?
                .parse()?;
            let index = surviving
                .iter()
                .position(|old| *old == original_index)
                .context("missing TOTP credential")?;
            if meta.get("totpFields").is_none() {
                meta["totpFields"] = json!([]);
            }
            let fields = meta["totpFields"]
                .as_array_mut()
                .context("invalid TOTP metadata")?;
            if let Some(existing) = fields.iter_mut().find(|entry| entry["index"] == index) {
                merge_field(
                    &mut existing["field"],
                    field,
                    baseline_fields[&key].1,
                    section,
                    &current.id,
                )?;
                existing["field"]
                    .as_object_mut()
                    .context("invalid TOTP field")?
                    .remove("value");
            } else {
                let encoded = SensitiveJson(export_field(field, section, &current.id)?);
                fields.push(json!({"index":index,"field":without(&encoded,"value")?}));
            }
        }
    }
    Ok(result.0.take())
}

fn merge_field(
    target: &mut Value,
    current: &PersonalField,
    old: &PersonalField,
    section: &PersonalSection,
    item: &str,
) -> anyhow::Result<()> {
    let value = match &current.value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        _ => bail!("CXF source field must remain text or Boolean"),
    };
    target["value"] = value.into();
    target["label"] = current.label.clone().into();
    if matches!(current.field_type, PersonalFieldType::Unknown(_)) {
        if current.field_type != old.field_type {
            bail!("unknown CXF field type changed");
        }
        return Ok(());
    }
    let encoded = SensitiveJson(export_field(current, section, item)?);
    if current.field_type != old.field_type || current.concealed != old.concealed {
        target["fieldType"] = encoded["fieldType"].clone();
    }
    let mut extensions = target
        .get_mut("extensions")
        .map_or_else(|| json!([]), Value::take);
    let values = extensions
        .as_array_mut()
        .context("invalid CXF field extensions")?;
    values.retain(|extension| extension["name"] != FIELD_EXTENSION);
    values.push(encoded["extensions"][0].clone());
    target["extensions"] = extensions;
    Ok(())
}

fn remove(root: &mut Value, path: &str) -> anyhow::Result<()> {
    let (parent, member) = path.rsplit_once('/').context("invalid CXF binding path")?;
    let target = root
        .pointer_mut(parent)
        .context("invalid CXF binding parent")?;
    if let Some(object) = target.as_object_mut() {
        if let Some(mut removed) = object.remove(&member.replace("~1", "/").replace("~0", "~")) {
            crate::personal::zeroize_json_strings(&mut removed);
        }
    } else {
        let value = root
            .pointer_mut(path)
            .context("invalid CXF binding element")?;
        crate::personal::zeroize_json_strings(value);
        *value = Value::Null;
    }
    Ok(())
}

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{Context as _, anyhow, bail};
use zeroize::Zeroizing;

pub mod cxf;
#[cfg(feature = "vault-client")]
pub mod import_plan;
mod onepux;
pub use crate::personal::{
    PersonalField, PersonalFieldType, PersonalSecret, PersonalSecretKind, PersonalSection,
};
use crate::personal::{
    legacy::{LegacyField, LegacyFieldSection, LegacySecret},
    zeroize_json_strings,
};

/// Decode a manager's in-memory payload. `CxfAge` expects decrypted CXF JSON;
/// file callers must authenticate it with `cxf::decrypt` or
/// `cxf::decrypt_with_hybrid_identity` first.
pub fn import_manager(format: TransferFormat, bytes: &[u8]) -> anyhow::Result<Vec<PersonalSecret>> {
    let mut items = import_manager_items(format, bytes)?;
    // An export can contain repeated source IDs. Preserve each record, with
    // deterministic replacement identities so retrying the import is idempotent.
    let mut reserved: HashSet<String> = items.iter().map(|item| item.id.clone()).collect();
    let mut seen = HashSet::new();
    for item in &mut items {
        if seen.insert(item.id.clone()) && item.has_storage_id() {
            continue;
        }
        let original = item.id.clone();
        let mut occurrence = 2_u64;
        loop {
            use sha2::{Digest as _, Sha256};
            let mut digest = Sha256::new();
            digest.update(b"factorseal/duplicate-import-id/v1\0");
            digest.update(original.as_bytes());
            digest.update(occurrence.to_be_bytes());
            let candidate = format!("duplicate-{}", hex::encode(digest.finalize()));
            if reserved.insert(candidate.clone()) {
                item.id = candidate;
                break;
            }
            occurrence += 1;
        }
    }
    Ok(items)
}

fn import_manager_items(
    format: TransferFormat,
    bytes: &[u8],
) -> anyhow::Result<Vec<PersonalSecret>> {
    if bytes.len() > MAX_MANAGER_FILE_BYTES {
        bail!("password-manager export is larger than 128 MiB");
    }
    if format == TransferFormat::OnePasswordPux {
        return onepux::import(bytes);
    }
    if format == TransferFormat::CxfAge {
        return cxf::import_json(bytes);
    }
    let mut items: Vec<_> = import_legacy_manager(format, bytes)?
        .into_iter()
        .map(PersonalSecret::from_legacy)
        .collect::<anyhow::Result<_>>()?;
    if format == TransferFormat::BitwardenJson {
        let root = SensitiveJson(serde_json::from_slice(bytes)?);
        for (item, original) in items.iter_mut().zip(
            root["items"]
                .as_array()
                .context("Bitwarden JSON has no items array")?,
        ) {
            map_additional_bitwarden_fields(item, original);
            if let Some(id) = string_at(original, "id") {
                item.id = format!("bitwarden-{id}");
            }
            let mut extra = SensitiveJson(original.clone());
            if let Some(object) = extra.0.as_object_mut() {
                for key in [
                    "id",
                    "name",
                    "type",
                    "notes",
                    "favorite",
                    "folderId",
                    "fields",
                    "card",
                    "identity",
                    "secureNote",
                ] {
                    if let Some(mut removed) = object.remove(key) {
                        zeroize_json_strings(&mut removed);
                    }
                }
                if let Some(login) = object
                    .get_mut("login")
                    .and_then(serde_json::Value::as_object_mut)
                {
                    for key in ["username", "password", "totp"] {
                        if let Some(mut removed) = login.remove(key) {
                            zeroize_json_strings(&mut removed);
                        }
                    }
                    if let Some(uris) = login
                        .get_mut("uris")
                        .and_then(serde_json::Value::as_array_mut)
                    {
                        for uri in uris.iter_mut() {
                            if let Some(obj) = uri.as_object_mut()
                                && let Some(mut removed) = obj.remove("uri")
                            {
                                zeroize_json_strings(&mut removed);
                            }
                        }
                    }
                }
            }
            prune_empty(&mut extra.0);
            let unusual = original["type"]
                .as_u64()
                .is_some_and(|n| !(1..=4).contains(&n))
                || original["fields"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|field| {
                        field["name"].as_str().is_none()
                            || (!field["value"].is_null() && !field["value"].is_string())
                            || field.as_object().is_some_and(|object| {
                                object.keys().any(|key| {
                                    !["name", "value", "type", "linkedId"].contains(&key.as_str())
                                })
                            })
                    })
                || ["card", "identity"].iter().any(|key| {
                    original[*key].as_object().is_some_and(|object| {
                        object.values().any(|v| !v.is_null() && !v.is_string())
                    })
                });
            if extra.0 != serde_json::json!({}) || unusual {
                item.source = Some(serde_json::json!({"format":"bitwarden", "item":original}));
            }
        }
    }
    Ok(items)
}

fn map_additional_bitwarden_fields(item: &mut PersonalSecret, original: &serde_json::Value) {
    let (kind, key) = match original["type"].as_u64() {
        Some(5) => (PersonalSecretKind::SshKey, "sshKey"),
        Some(6) => (PersonalSecretKind::BankAccount, "bankAccount"),
        Some(8) => (PersonalSecretKind::Passport, "passport"),
        _ => return,
    };
    item.kind = kind;
    if let Some(object) = original[key].as_object() {
        item.sections.push(PersonalSection {
            id: key.into(),
            label: kind.label().into(),
            fields: object
                .iter()
                .map(|(name, value)| {
                    let ty = match (name.as_str(), value.is_string()) {
                        ("privateKey", true) => PersonalFieldType::SshKey,
                        ("publicKey", true) => PersonalFieldType::Multiline,
                        (_, true) => PersonalFieldType::Concealed,
                        _ => PersonalFieldType::Unknown(format!("bitwarden-{key}")),
                    };
                    PersonalField::new(name.clone(), name.clone(), ty, value.clone())
                })
                .collect(),
        });
    }
}

fn prune_empty(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for child in object.values_mut() {
                prune_empty(child);
            }
            object.retain(|_, v| {
                !v.is_null() && v != &serde_json::json!({}) && v != &serde_json::json!([])
            });
        }
        serde_json::Value::Array(array) => {
            for child in array.iter_mut() {
                prune_empty(child);
            }
            if array
                .iter()
                .all(|v| v.is_null() || v == &serde_json::json!({}))
            {
                array.clear();
            }
        }
        _ => {}
    }
}

/// Encode a plaintext manager payload. For `CxfAge`, file callers must pass
/// the returned JSON through `cxf::encrypt` or `cxf::encrypt_to_recipient`
/// before writing it.
pub fn export_manager(
    format: TransferFormat,
    secrets: &[PersonalSecret],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if format == TransferFormat::CxfAge {
        return cxf::export_json(secrets);
    }
    let legacy = secrets
        .iter()
        .map(PersonalSecret::to_legacy)
        .collect::<anyhow::Result<Vec<_>>>()?;
    let encoded = export_legacy_manager(format, &legacy)?;
    if format == TransferFormat::BitwardenJson {
        let mut root = SensitiveJson(serde_json::from_slice(&encoded)?);
        for (item, secret) in root.0["items"]
            .as_array_mut()
            .context("invalid generated Bitwarden items")?
            .iter_mut()
            .zip(secrets)
        {
            item["id"] = secret
                .id
                .strip_prefix("bitwarden-")
                .unwrap_or(&secret.id)
                .into();
        }
        return serde_json::to_vec_pretty(&root.0)
            .map(Zeroizing::new)
            .context("could not encode Bitwarden JSON");
    }
    Ok(encoded)
}

#[must_use]
pub fn personal_import_names(secrets: &[PersonalSecret]) -> Vec<String> {
    unique_import_names(secrets.iter().map(|secret| secret.title.as_str()))
}

/// Items containing data retained for backup without full functional support.
#[must_use]
pub fn preserved_only_items(secrets: &[PersonalSecret]) -> usize {
    secrets
        .iter()
        .filter(|item| {
            item.source
                .as_ref()
                .is_some_and(|source| source["format"] != "cxf" || source["unsupported"] != false)
                || item
                    .sections
                    .iter()
                    .flat_map(|section| &section.fields)
                    .any(|field| matches!(field.field_type, PersonalFieldType::Unknown(_)))
        })
        .count()
}

#[cfg(test)]
#[path = "transfer/fixture_tests.rs"]
mod fixture_tests;

const MAX_MANAGER_FILE_BYTES: usize = 128 * 1024 * 1024;
const MAX_MANAGER_ITEMS: usize = 100_000;
const MAX_TRANSFER_FILE_BYTES: u64 = 256 * 1024 * 1024;

struct SensitiveJson(serde_json::Value);

impl std::ops::Deref for SensitiveJson {
    type Target = serde_json::Value;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveJson {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransferFormat {
    #[default]
    FactorSeal,
    CxfAge,
    BitwardenJson,
    OnePasswordCsv,
    OnePasswordPux,
    KeePassCsv,
}

impl TransferFormat {
    pub const ALL: [Self; 6] = [
        Self::FactorSeal,
        Self::CxfAge,
        Self::BitwardenJson,
        Self::OnePasswordCsv,
        Self::OnePasswordPux,
        Self::KeePassCsv,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FactorSeal => "FactorSeal archive",
            Self::CxfAge => "Credential Exchange (age encrypted)",
            Self::BitwardenJson => "Bitwarden JSON",
            Self::OnePasswordCsv => "1Password CSV",
            Self::OnePasswordPux => "1Password 1PUX",
            Self::KeePassCsv => "KeePass CSV",
        }
    }

    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::FactorSeal => "factorseal",
            Self::CxfAge => "age",
            Self::BitwardenJson => "json",
            Self::OnePasswordCsv | Self::KeePassCsv => "csv",
            Self::OnePasswordPux => "1pux",
        }
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::FactorSeal)
    }

    #[must_use]
    pub const fn is_encrypted(self) -> bool {
        matches!(self, Self::FactorSeal | Self::CxfAge)
    }
}

fn import_legacy_manager(
    format: TransferFormat,
    bytes: &[u8],
) -> anyhow::Result<Vec<LegacySecret>> {
    if bytes.len() > MAX_MANAGER_FILE_BYTES {
        bail!("password-manager export is larger than 128 MiB");
    }
    let secrets = match format {
        TransferFormat::BitwardenJson => import_bitwarden(bytes)?,
        TransferFormat::OnePasswordCsv => import_one_password(bytes)?,
        TransferFormat::KeePassCsv => import_keepass(bytes)?,
        TransferFormat::FactorSeal => bail!("native archives use the encrypted archive reader"),
        TransferFormat::CxfAge => bail!("CXF uses the structured item reader"),
        TransferFormat::OnePasswordPux => bail!("1PUX uses the structured item reader"),
    };
    if secrets.len() > MAX_MANAGER_ITEMS {
        bail!("password-manager export contains too many items");
    }
    Ok(secrets)
}

/// Assign stable, unique addresses within an import, reserving original titles
/// before allocating suffixes. Destination conflicts are handled by the vault.
#[must_use]
#[cfg(test)]
fn legacy_import_names(secrets: &[LegacySecret]) -> Vec<String> {
    unique_import_names(secrets.iter().map(|secret| secret.title.as_str()))
}

fn unique_import_names<'a>(titles: impl Iterator<Item = &'a str> + Clone) -> Vec<String> {
    let mut reserved: HashSet<String> = titles.clone().map(str::to_owned).collect();
    let mut seen = HashMap::<&str, u64>::new();
    titles
        .map(|title| {
            let suffix = seen.entry(title).or_insert(1);
            if *suffix == 1 {
                *suffix = 2;
                return title.to_owned();
            }
            loop {
                let name = format!("{title} ({suffix})");
                *suffix += 1;
                if reserved.insert(name.clone()) {
                    return name;
                }
            }
        })
        .collect()
}

fn export_legacy_manager(
    format: TransferFormat,
    secrets: &[LegacySecret],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    validate_manager_export(format, secrets)?;
    match format {
        TransferFormat::BitwardenJson => export_bitwarden(secrets),
        TransferFormat::OnePasswordCsv => export_one_password(secrets),
        TransferFormat::KeePassCsv => export_keepass(secrets),
        TransferFormat::FactorSeal => bail!("native archives use the encrypted archive writer"),
        TransferFormat::CxfAge => bail!("CXF uses the structured item writer"),
        TransferFormat::OnePasswordPux => {
            bail!("1PUX is import-only; use an encrypted FactorSeal archive to export")
        }
    }
}

fn validate_manager_export(format: TransferFormat, secrets: &[LegacySecret]) -> anyhow::Result<()> {
    for secret in secrets {
        let lossy = match format {
            TransferFormat::FactorSeal => false,
            TransferFormat::CxfAge | TransferFormat::OnePasswordPux => true,
            TransferFormat::BitwardenJson => secret.archived || !secret.tags.is_empty(),
            TransferFormat::OnePasswordCsv | TransferFormat::KeePassCsv => {
                !matches!(
                    secret.kind,
                    PersonalSecretKind::Login | PersonalSecretKind::Generic
                ) || !secret.custom_fields.is_empty()
                    || secret.urls.len() > 1
                    || secret.folder.is_some()
                    || (format == TransferFormat::KeePassCsv
                        && (secret.totp.is_some()
                            || secret.favorite
                            || secret.archived
                            || !secret.tags.is_empty()))
                    || secret
                        .tags
                        .iter()
                        .any(|tag| tag.contains(',') || tag.trim() != tag || tag.is_empty())
            }
        };
        if lossy {
            bail!(
                "{} cannot preserve all item types, secret fields or metadata in this vault; use an encrypted FactorSeal archive for a lossless export",
                format.label()
            );
        }
    }
    Ok(())
}

pub fn read_transfer_file(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    crate::security::read_regular_file(path, MAX_TRANSFER_FILE_BYTES)
        .with_context(|| format!("could not read {}", path.display()))
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    crate::security::write_private_file(path, bytes)
        .with_context(|| format!("could not write private file {}", path.display()))
}

fn import_bitwarden(bytes: &[u8]) -> anyhow::Result<Vec<LegacySecret>> {
    let root = SensitiveJson(serde_json::from_slice(bytes).context("invalid Bitwarden JSON")?);
    if root.get("encrypted").and_then(serde_json::Value::as_bool) == Some(true) {
        bail!("encrypted Bitwarden exports are not supported; export unencrypted JSON instead");
    }
    let folders = root
        .get("folders")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|folder| {
            Some((
                folder.get("id")?.as_str()?.to_owned(),
                folder.get("name")?.as_str()?.to_owned(),
            ))
        })
        .collect::<HashMap<_, _>>();
    let items = root
        .get("items")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("Bitwarden JSON has no items array"))?;
    items
        .iter()
        .map(|item| bitwarden_item(item, &folders))
        .collect()
}

fn bitwarden_item(
    item: &serde_json::Value,
    folders: &HashMap<String, String>,
) -> anyhow::Result<LegacySecret> {
    let item_type = item
        .get("type")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(1);
    let kind = match item_type {
        1 => PersonalSecretKind::Login,
        2 => PersonalSecretKind::SecureNote,
        3 => PersonalSecretKind::Card,
        4 => PersonalSecretKind::Identity,
        _ => PersonalSecretKind::Generic,
    };
    let title = item
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| anyhow!("Bitwarden item has no name"))?
        .to_owned();
    let mut secret = LegacySecret::new(kind, title);
    secret.notes = string_at(item, "notes");
    secret.favorite = item
        .get("favorite")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    secret.folder = item
        .get("folderId")
        .and_then(serde_json::Value::as_str)
        .and_then(|id| folders.get(id))
        .cloned();
    if let Some(login) = item.get("login") {
        secret.username = string_at(login, "username");
        secret.password = string_at(login, "password");
        secret.totp = string_at(login, "totp");
        secret.urls = login
            .get("uris")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|uri| string_at(uri, "uri"))
            .collect();
    }
    if let Some(fields) = item.get("fields").and_then(serde_json::Value::as_array) {
        secret.custom_fields.extend(fields.iter().map(|field| {
            LegacyField {
                name: field
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                value: string_at(field, "value").unwrap_or_default(),
                section: LegacyFieldSection::Custom,
                field_type: field
                    .get("type")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
                linked_id: field.get("linkedId").and_then(serde_json::Value::as_u64),
            }
        }));
    }
    let object_name = match kind {
        PersonalSecretKind::Card => Some("card"),
        PersonalSecretKind::Identity => Some("identity"),
        _ => None,
    };
    if let Some(object) = object_name
        .and_then(|name| item.get(name))
        .and_then(serde_json::Value::as_object)
    {
        secret
            .custom_fields
            .extend(object.iter().filter_map(|(name, value)| {
                value
                    .as_str()
                    .and_then(|value| nonempty(value.to_owned()))
                    .map(|value| LegacyField {
                        name: name.clone(),
                        value,
                        field_type: 0,
                        linked_id: None,
                        section: if kind == PersonalSecretKind::Card {
                            LegacyFieldSection::Card
                        } else {
                            LegacyFieldSection::Identity
                        },
                    })
            }));
    }
    Ok(secret)
}

fn export_bitwarden(secrets: &[LegacySecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut folders = Vec::<serde_json::Value>::new();
    let mut folder_ids = HashMap::<&str, String>::new();
    for secret in secrets {
        if let Some(folder) = secret.folder.as_deref()
            && !folder_ids.contains_key(folder)
        {
            let id = uuid::Uuid::new_v4().to_string();
            folders.push(serde_json::json!({ "id": id, "name": folder }));
            folder_ids.insert(folder, id);
        }
    }
    let items = secrets
        .iter()
        .map(|secret| {
            let item_type = match secret.kind {
                PersonalSecretKind::SecureNote => 2,
                PersonalSecretKind::Card => 3,
                PersonalSecretKind::Identity => 4,
                _ => 1,
            };
            let fields = secret
                .custom_fields
                .iter()
                .filter(|field| field.section == LegacyFieldSection::Custom)
                .map(|field| {
                    let mut value = serde_json::json!({ "name": field.name, "value": field.value, "type": field.field_type });
                    if let Some(id) = field.linked_id { value["linkedId"] = id.into(); }
                    value
                })
                .collect::<Vec<_>>();
            let mut item = serde_json::json!({
                "id": uuid::Uuid::new_v4().to_string(),
                "organizationId": null,
                "folderId": secret.folder.as_deref().and_then(|folder| folder_ids.get(folder)),
                "type": item_type,
                "reprompt": 0,
                "name": secret.title,
                "notes": secret.notes,
                "favorite": secret.favorite,
                "fields": fields,
            });
            match secret.kind {
                PersonalSecretKind::Login | PersonalSecretKind::Generic => {
                    item["login"] = serde_json::json!({
                        "uris": secret.urls.iter().map(|uri| serde_json::json!({ "match": null, "uri": uri })).collect::<Vec<_>>(),
                        "username": secret.username,
                        "password": secret.password,
                        "totp": secret.totp,
                    });
                }
                PersonalSecretKind::SecureNote => {
                    item["secureNote"] = serde_json::json!({ "type": 0 });
                }
                PersonalSecretKind::Card => {
                    item["card"] =
                        fields_as_object(&secret.custom_fields, LegacyFieldSection::Card);
                }
                PersonalSecretKind::Identity => {
                    item["identity"] =
                        fields_as_object(&secret.custom_fields, LegacyFieldSection::Identity);
                }
                _ => unreachable!("unsupported categories rejected before export"),
            }
            item
        })
        .collect::<Vec<_>>();
    let root = SensitiveJson(serde_json::json!({
        "encrypted": false,
        "folders": folders,
        "items": items,
    }));
    serde_json::to_vec_pretty(&root.0)
        .map(Zeroizing::new)
        .context("could not encode Bitwarden JSON")
}

fn fields_as_object(fields: &[LegacyField], section: LegacyFieldSection) -> serde_json::Value {
    serde_json::Value::Object(
        fields
            .iter()
            .filter(|field| field.section == section)
            .map(|field| {
                (
                    field.name.clone(),
                    serde_json::Value::String(field.value.clone()),
                )
            })
            .collect(),
    )
}

fn import_one_password(bytes: &[u8]) -> anyhow::Result<Vec<LegacySecret>> {
    import_csv(bytes, CsvFlavor::OnePassword)
}

fn import_keepass(bytes: &[u8]) -> anyhow::Result<Vec<LegacySecret>> {
    import_csv(bytes, CsvFlavor::KeePass)
}

#[derive(Clone, Copy)]
enum CsvFlavor {
    OnePassword,
    KeePass,
}

#[allow(clippy::too_many_lines)]
fn import_csv(bytes: &[u8], flavor: CsvFlavor) -> anyhow::Result<Vec<LegacySecret>> {
    let mut builder = csv::ReaderBuilder::new();
    builder.flexible(true);
    // KeePass 1.x quotes every column and escapes quotes and backslashes with
    // a backslash. Keep accepting the unquoted RFC CSV header emitted by older
    // FactorSeal versions, as well as KeePassX's Title/Username dialect.
    let without_bom = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    if matches!(flavor, CsvFlavor::KeePass)
        && without_bom.starts_with(b"\"Account\",\"Login Name\",")
    {
        builder.escape(Some(b'\\')).double_quote(false);
    }
    let mut reader = builder.from_reader(bytes);
    let headers = reader.headers().context("invalid CSV header")?.clone();
    let index = headers
        .iter()
        .enumerate()
        .map(|(index, name)| (normalized_header(name), index))
        .collect::<HashMap<_, _>>();
    let title_names: &[&str] = match flavor {
        CsvFlavor::OnePassword => &["title"],
        CsvFlavor::KeePass => &["account", "title"],
    };
    let mut output = Vec::new();
    let known: &[&str] = match flavor {
        CsvFlavor::OnePassword => &[
            "title",
            "website",
            "url",
            "username",
            "password",
            "one-timepassword",
            "onetimepassword",
            "otpauth",
            "favoritestatus",
            "favorite",
            "archivedstatus",
            "archived",
            "tags",
            "notes",
        ],
        CsvFlavor::KeePass => &[
            "account",
            "title",
            "loginname",
            "username",
            "password",
            "website",
            "url",
            "comments",
            "notes",
        ],
    };
    let mut unique = HashSet::new();
    if headers.iter().any(|h| !unique.insert(normalized_header(h))) {
        bail!("CSV contains duplicate column names");
    }
    for aliases in [
        &["title", "account"][..],
        &["website", "url"][..],
        &["username", "loginname"][..],
        &["one-timepassword", "onetimepassword", "otpauth"][..],
        &["favoritestatus", "favorite"][..],
        &["archivedstatus", "archived"][..],
        &["comments", "notes"][..],
    ] {
        if aliases
            .iter()
            .filter(|alias| known.contains(alias) && index.contains_key(**alias))
            .count()
            > 1
        {
            bail!("CSV contains multiple columns for the same field");
        }
    }
    for row in reader.records() {
        let row = row.context("invalid CSV row")?;
        if row.len() > headers.len() {
            bail!("CSV row has values without column names");
        }
        let title = csv_value(&row, &index, title_names)
            .ok_or_else(|| anyhow!("CSV row has no item title"))?;
        let mut secret = LegacySecret::new(PersonalSecretKind::Login, title);
        match flavor {
            CsvFlavor::OnePassword => {
                secret.urls = csv_value(&row, &index, &["website", "url"])
                    .into_iter()
                    .collect();
                secret.username = csv_value(&row, &index, &["username"]);
                secret.password = csv_value(&row, &index, &["password"]);
                secret.totp = csv_value(
                    &row,
                    &index,
                    &["one-timepassword", "onetimepassword", "otpauth"],
                );
                secret.favorite = csv_value(&row, &index, &["favoritestatus", "favorite"])
                    .is_some_and(|value| parse_bool(&value));
                secret.archived = csv_value(&row, &index, &["archivedstatus", "archived"])
                    .is_some_and(|value| parse_bool(&value));
                secret.tags = csv_value(&row, &index, &["tags"])
                    .map(|value| {
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|tag| !tag.is_empty())
                            .map(ToOwned::to_owned)
                            .collect()
                    })
                    .unwrap_or_default();
                secret.notes = csv_value(&row, &index, &["notes"]);
            }
            CsvFlavor::KeePass => {
                secret.username = csv_value(&row, &index, &["loginname", "username"]);
                secret.password = csv_value(&row, &index, &["password"]);
                secret.urls = csv_value(&row, &index, &["website", "url"])
                    .into_iter()
                    .collect();
                secret.notes = csv_value(&row, &index, &["comments", "notes"]);
            }
        }
        for (column, label) in headers.iter().enumerate() {
            if !known.contains(&normalized_header(label).as_str()) {
                secret.custom_fields.push(LegacyField {
                    name: label.into(),
                    value: row.get(column).unwrap_or_default().into(),
                    section: LegacyFieldSection::Custom,
                    field_type: 1,
                    linked_id: None,
                });
            }
        }
        output.push(secret);
        if output.len() > MAX_MANAGER_ITEMS {
            bail!("password-manager export contains too many items");
        }
    }
    Ok(output)
}

fn export_one_password(secrets: &[LegacySecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    export_csv(secrets, CsvFlavor::OnePassword)
}

fn export_keepass(secrets: &[LegacySecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    export_csv(secrets, CsvFlavor::KeePass)
}

fn export_csv(secrets: &[LegacySecret], flavor: CsvFlavor) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut builder = csv::WriterBuilder::new();
    if matches!(flavor, CsvFlavor::KeePass) {
        builder
            .quote_style(csv::QuoteStyle::Always)
            .double_quote(false)
            .escape(b'\\');
    }
    let mut writer = builder.from_writer(Vec::new());
    match flavor {
        CsvFlavor::OnePassword => writer.write_record([
            "Title",
            "Website",
            "Username",
            "Password",
            "One-time password",
            "Favorite status",
            "Archived status",
            "Tags",
            "Notes",
        ])?,
        CsvFlavor::KeePass => {
            writer.write_record(["Account", "Login Name", "Password", "Web Site", "Comments"])?;
        }
    }
    for secret in secrets {
        match flavor {
            CsvFlavor::OnePassword => writer.write_record([
                secret.title.as_str(),
                secret.urls.first().map_or("", String::as_str),
                secret.username.as_deref().unwrap_or_default(),
                secret.password.as_deref().unwrap_or_default(),
                secret.totp.as_deref().unwrap_or_default(),
                if secret.favorite { "true" } else { "false" },
                if secret.archived { "true" } else { "false" },
                &secret.tags.join(", "),
                secret.notes.as_deref().unwrap_or_default(),
            ])?,
            CsvFlavor::KeePass => writer.write_record(
                Zeroizing::new(
                    [
                        secret.title.as_str(),
                        secret.username.as_deref().unwrap_or_default(),
                        secret.password.as_deref().unwrap_or_default(),
                        secret.urls.first().map_or("", String::as_str),
                        secret.notes.as_deref().unwrap_or_default(),
                    ]
                    .into_iter()
                    .map(|value| value.replace('\\', "\\\\"))
                    .collect::<Vec<_>>(),
                )
                .iter(),
            )?,
        }
    }
    writer
        .into_inner()
        .map(Zeroizing::new)
        .map_err(|error| anyhow!("could not finish CSV export: {error}"))
}

fn csv_value(
    row: &csv::StringRecord,
    index: &HashMap<String, usize>,
    names: &[&str],
) -> Option<String> {
    names.iter().find_map(|name| {
        index
            .get(*name)
            .and_then(|index| row.get(*index))
            .and_then(|value| nonempty(value.to_owned()))
    })
}

fn normalized_header(name: &str) -> String {
    name.trim()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect()
}

fn string_at(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .and_then(|value| nonempty(value.to_owned()))
}

fn nonempty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}

fn parse_bool(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_source_ids_are_preserved_and_repeatable() {
        let bytes = br#"{"items":[
            {"id":"repeated","type":1,"name":"Same title","login":{"password":"first"}},
            {"id":"repeated","type":1,"name":"Same title","login":{"password":"second"}}
        ]}"#;
        let first = import_manager(TransferFormat::BitwardenJson, bytes).unwrap();
        let second = import_manager(TransferFormat::BitwardenJson, bytes).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
        assert_ne!(first[0].id, first[1].id);
        assert_eq!(first[0].title, first[1].title);
        assert_eq!(first[0].sections[0].fields[0].text(), Some("first"));
        assert_eq!(first[1].sections[0].fields[0].text(), Some("second"));
    }

    #[test]
    fn structured_personal_secret_round_trips_and_legacy_is_supported() {
        let secret = LegacySecret::generic("API token".to_owned(), "needle".to_owned());
        let encoded = secret.encode().unwrap();
        let decoded = LegacySecret::decode("wrong title", &encoded).unwrap();
        assert_eq!(decoded.title, "API token");
        assert_eq!(decoded.password.as_deref(), Some("needle"));

        let legacy = LegacySecret::decode("Legacy", b"old value").unwrap();
        assert_eq!(legacy.title, "Legacy");
        assert_eq!(legacy.password.as_deref(), Some("old value"));

        let future = br#"{"format":"factorseal-personal-secret","version":2,"kind":"generic","title":"Future"}"#;
        assert!(LegacySecret::decode("Future", future).is_err());
    }

    #[test]
    fn bitwarden_json_preserves_login_fields() {
        let source = br#"{
          "encrypted": false,
          "folders": [{"id":"work","name":"Work"}],
          "items": [{
            "type":1,"name":"Example","folderId":"work","favorite":true,"notes":"note",
            "login":{"username":"user","password":"pass","totp":"seed","uris":[{"uri":"https://example.com"}]},
            "fields":[{"name":"recovery","value":"code","type":0}]
          }]
        }"#;
        let imported = import_legacy_manager(TransferFormat::BitwardenJson, source).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].folder.as_deref(), Some("Work"));
        assert_eq!(imported[0].totp.as_deref(), Some("seed"));
        assert_eq!(imported[0].custom_fields[0].value, "code");
        let exported = export_legacy_manager(TransferFormat::BitwardenJson, &imported).unwrap();
        let again = import_legacy_manager(TransferFormat::BitwardenJson, &exported).unwrap();
        assert_eq!(again[0].username.as_deref(), Some("user"));
        assert_eq!(again[0].urls, ["https://example.com"]);
    }

    #[test]
    fn bitwarden_card_fields_remain_card_fields() {
        let source = br#"{
          "items": [{
            "type":3,"name":"Payment card","card":{"cardholderName":"Ada","number":"4111"},
            "fields":[{"name":"support pin","value":"1234","type":0}]
          }]
        }"#;
        let imported = import_legacy_manager(TransferFormat::BitwardenJson, source).unwrap();
        let exported = export_legacy_manager(TransferFormat::BitwardenJson, &imported).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&exported).unwrap();
        let item = &value["items"][0];
        assert_eq!(item["card"]["cardholderName"], "Ada");
        assert_eq!(item["fields"].as_array().unwrap().len(), 1);
        assert_eq!(item["fields"][0]["name"], "support pin");
    }

    #[test]
    fn one_password_csv_uses_official_columns() {
        let source = b"Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\nExample,https://example.com,user,pass,seed,true,false,work,note\n";
        let imported = import_legacy_manager(TransferFormat::OnePasswordCsv, source).unwrap();
        assert_eq!(imported[0].password.as_deref(), Some("pass"));
        assert!(imported[0].favorite);
        let exported = export_legacy_manager(TransferFormat::OnePasswordCsv, &imported).unwrap();
        assert!(String::from_utf8_lossy(&exported).starts_with("Title,Website,Username"));
        let again = import_legacy_manager(TransferFormat::OnePasswordCsv, &exported).unwrap();
        assert_eq!(again[0].totp.as_deref(), Some("seed"));
    }

    #[test]
    fn keepass_csv_uses_official_columns() {
        let source = b"Account,Login Name,Password,Web Site,Comments\nExample,user,pass,https://example.com,note\n";
        let imported = import_legacy_manager(TransferFormat::KeePassCsv, source).unwrap();
        assert_eq!(imported[0].username.as_deref(), Some("user"));
        let exported = export_legacy_manager(TransferFormat::KeePassCsv, &imported).unwrap();
        assert!(String::from_utf8_lossy(&exported).starts_with("\"Account\",\"Login Name\""));
        let again = import_legacy_manager(TransferFormat::KeePassCsv, &exported).unwrap();
        assert_eq!(again[0].notes.as_deref(), Some("note"));
    }

    #[cfg(unix)]
    #[test]
    fn transfer_files_are_user_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("export.csv");
        write_private_file(&path, b"secret").unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    #[test]
    fn duplicate_import_names_reserve_original_titles_and_are_repeatable() {
        let secrets = ["A", "A", "A (2)", "A", "A (3)", "A (2)"]
            .into_iter()
            .map(|title| LegacySecret::generic(title.into(), "value".into()))
            .collect::<Vec<_>>();
        let expected = vec!["A", "A (4)", "A (2)", "A (5)", "A (3)", "A (2) (2)"];
        assert_eq!(legacy_import_names(&secrets), expected);
        assert_eq!(legacy_import_names(&secrets), expected);
    }

    #[test]
    fn csv_exports_reject_lossy_items_before_writing() {
        let source = br#"{"items":[{"name":"Card","type":3,"card":{"number":"4111111111111111","code":"123"}}]}"#;
        let cards = import_legacy_manager(TransferFormat::BitwardenJson, source).unwrap();
        for format in [TransferFormat::OnePasswordCsv, TransferFormat::KeePassCsv] {
            assert!(
                export_legacy_manager(format, &cards)
                    .unwrap_err()
                    .to_string()
                    .contains("lossless")
            );
            let mut login = LegacySecret::generic("Login".into(), "value".into());
            login.urls = vec!["https://one.test".into(), "https://two.test".into()];
            assert!(export_legacy_manager(format, &[login]).is_err());
        }
        let mut login = LegacySecret::generic("Login".into(), "value".into());
        login.totp = Some("OTP-SEED".into());
        assert!(export_legacy_manager(TransferFormat::KeePassCsv, &[login]).is_err());
        let encoded = export_legacy_manager(TransferFormat::BitwardenJson, &cards).unwrap();
        let restored = import_legacy_manager(TransferFormat::BitwardenJson, &encoded).unwrap();
        assert_eq!(restored[0].custom_fields.len(), 2);
    }
}

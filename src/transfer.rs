use std::collections::HashMap;
use std::path::Path;

use anyhow::{Context as _, anyhow, bail};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const PERSONAL_FORMAT: &str = "factorseal-personal-secret";
const PERSONAL_VERSION: u16 = 1;
const MAX_MANAGER_FILE_BYTES: usize = 128 * 1024 * 1024;
const MAX_MANAGER_ITEMS: usize = 100_000;
const MAX_TRANSFER_FILE_BYTES: u64 = 256 * 1024 * 1024;

struct SensitiveJson(serde_json::Value);

#[derive(Deserialize)]
struct PersonalHeader<'a> {
    #[serde(borrow)]
    format: Option<&'a str>,
    version: Option<u16>,
}

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

fn zeroize_json_strings(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(value) => value.zeroize(),
        serde_json::Value::Array(values) => {
            for value in values {
                zeroize_json_strings(value);
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_strings(value);
            }
        }
        serde_json::Value::Null | serde_json::Value::Bool(_) | serde_json::Value::Number(_) => {}
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransferFormat {
    #[default]
    FactorSeal,
    BitwardenJson,
    OnePasswordCsv,
    KeePassCsv,
}

impl TransferFormat {
    pub const ALL: [Self; 4] = [
        Self::FactorSeal,
        Self::BitwardenJson,
        Self::OnePasswordCsv,
        Self::KeePassCsv,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FactorSeal => "FactorSeal archive",
            Self::BitwardenJson => "Bitwarden JSON",
            Self::OnePasswordCsv => "1Password CSV",
            Self::KeePassCsv => "KeePass CSV",
        }
    }

    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::FactorSeal => "factorseal",
            Self::BitwardenJson => "json",
            Self::OnePasswordCsv | Self::KeePassCsv => "csv",
        }
    }

    #[must_use]
    pub const fn is_native(self) -> bool {
        matches!(self, Self::FactorSeal)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PersonalSecretKind {
    Login,
    SecureNote,
    Card,
    Identity,
    #[default]
    Generic,
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PersonalField {
    pub(crate) name: String,
    pub(crate) value: String,
    #[serde(default, skip_serializing_if = "PersonalFieldSection::is_custom")]
    section: PersonalFieldSection,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PersonalFieldSection {
    #[default]
    Custom,
    Card,
    Identity,
}

impl PersonalFieldSection {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_custom(&self) -> bool {
        matches!(self, Self::Custom)
    }
}

impl Drop for PersonalField {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalSecret {
    format: String,
    version: u16,
    kind: PersonalSecretKind,
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) password: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) totp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) notes: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) custom_fields: Vec<PersonalField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) folder: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) tags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) favorite: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) archived: bool,
}

impl PersonalSecret {
    #[must_use]
    pub fn generic(title: String, value: String) -> Self {
        Self {
            format: PERSONAL_FORMAT.to_owned(),
            version: PERSONAL_VERSION,
            kind: PersonalSecretKind::Generic,
            title,
            username: None,
            password: nonempty(value),
            urls: Vec::new(),
            totp: None,
            notes: None,
            custom_fields: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            archived: false,
        }
    }

    pub fn encode(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .context("could not encode personal secret")
    }

    pub fn decode(title: &str, bytes: &[u8]) -> anyhow::Result<Self> {
        if let Ok(header) = serde_json::from_slice::<PersonalHeader<'_>>(bytes)
            && header.format == Some(PERSONAL_FORMAT)
        {
            if header.version != Some(PERSONAL_VERSION) {
                bail!("unsupported FactorSeal personal-secret version");
            }
            let secret: Self = serde_json::from_slice(bytes)
                .context("invalid FactorSeal personal-secret record")?;
            if !secret.is_supported() {
                bail!("unsupported FactorSeal personal-secret version");
            }
            return Ok(secret);
        }
        Ok(Self::generic(
            title.to_owned(),
            String::from_utf8_lossy(bytes).into_owned(),
        ))
    }

    fn is_supported(&self) -> bool {
        self.format == PERSONAL_FORMAT && self.version == PERSONAL_VERSION
    }

    fn new(kind: PersonalSecretKind, title: String) -> Self {
        Self {
            format: PERSONAL_FORMAT.to_owned(),
            version: PERSONAL_VERSION,
            kind,
            title,
            username: None,
            password: None,
            urls: Vec::new(),
            totp: None,
            notes: None,
            custom_fields: Vec::new(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            archived: false,
        }
    }
}

impl Drop for PersonalSecret {
    fn drop(&mut self) {
        self.title.zeroize();
        self.username.zeroize();
        self.password.zeroize();
        self.urls.zeroize();
        self.totp.zeroize();
        self.notes.zeroize();
        self.folder.zeroize();
        self.tags.zeroize();
    }
}

pub fn import_manager(format: TransferFormat, bytes: &[u8]) -> anyhow::Result<Vec<PersonalSecret>> {
    if bytes.len() > MAX_MANAGER_FILE_BYTES {
        bail!("password-manager export is larger than 128 MiB");
    }
    let secrets = match format {
        TransferFormat::BitwardenJson => import_bitwarden(bytes)?,
        TransferFormat::OnePasswordCsv => import_one_password(bytes)?,
        TransferFormat::KeePassCsv => import_keepass(bytes)?,
        TransferFormat::FactorSeal => bail!("native archives use the encrypted archive reader"),
    };
    if secrets.len() > MAX_MANAGER_ITEMS {
        bail!("password-manager export contains too many items");
    }
    Ok(secrets)
}

pub fn export_manager(
    format: TransferFormat,
    secrets: &[PersonalSecret],
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    match format {
        TransferFormat::BitwardenJson => export_bitwarden(secrets),
        TransferFormat::OnePasswordCsv => export_one_password(secrets),
        TransferFormat::KeePassCsv => export_keepass(secrets),
        TransferFormat::FactorSeal => bail!("native archives use the encrypted archive writer"),
    }
}

pub fn read_transfer_file(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    crate::security::read_regular_file(path, MAX_TRANSFER_FILE_BYTES)
        .with_context(|| format!("could not read {}", path.display()))
}

pub fn write_private_file(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    crate::security::write_private_file(path, bytes)
        .with_context(|| format!("could not write private file {}", path.display()))
}

fn import_bitwarden(bytes: &[u8]) -> anyhow::Result<Vec<PersonalSecret>> {
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
) -> anyhow::Result<PersonalSecret> {
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
    let mut secret = PersonalSecret::new(kind, title);
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
        secret
            .custom_fields
            .extend(fields.iter().filter_map(|field| {
                Some(PersonalField {
                    name: string_at(field, "name")?,
                    value: string_at(field, "value").unwrap_or_default(),
                    section: PersonalFieldSection::Custom,
                })
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
                    .map(|value| PersonalField {
                        name: name.clone(),
                        value,
                        section: if kind == PersonalSecretKind::Card {
                            PersonalFieldSection::Card
                        } else {
                            PersonalFieldSection::Identity
                        },
                    })
            }));
    }
    Ok(secret)
}

fn export_bitwarden(secrets: &[PersonalSecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
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
                PersonalSecretKind::Login | PersonalSecretKind::Generic => 1,
                PersonalSecretKind::SecureNote => 2,
                PersonalSecretKind::Card => 3,
                PersonalSecretKind::Identity => 4,
            };
            let fields = secret
                .custom_fields
                .iter()
                .filter(|field| field.section == PersonalFieldSection::Custom)
                .map(|field| serde_json::json!({ "name": field.name, "value": field.value, "type": 0 }))
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
                        fields_as_object(&secret.custom_fields, PersonalFieldSection::Card);
                }
                PersonalSecretKind::Identity => {
                    item["identity"] =
                        fields_as_object(&secret.custom_fields, PersonalFieldSection::Identity);
                }
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

fn fields_as_object(fields: &[PersonalField], section: PersonalFieldSection) -> serde_json::Value {
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

fn import_one_password(bytes: &[u8]) -> anyhow::Result<Vec<PersonalSecret>> {
    import_csv(bytes, CsvFlavor::OnePassword)
}

fn import_keepass(bytes: &[u8]) -> anyhow::Result<Vec<PersonalSecret>> {
    import_csv(bytes, CsvFlavor::KeePass)
}

#[derive(Clone, Copy)]
enum CsvFlavor {
    OnePassword,
    KeePass,
}

fn import_csv(bytes: &[u8], flavor: CsvFlavor) -> anyhow::Result<Vec<PersonalSecret>> {
    let mut reader = csv::ReaderBuilder::new().flexible(true).from_reader(bytes);
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
    for row in reader.records() {
        let row = row.context("invalid CSV row")?;
        let title = csv_value(&row, &index, title_names)
            .ok_or_else(|| anyhow!("CSV row has no item title"))?;
        let mut secret = PersonalSecret::new(PersonalSecretKind::Login, title);
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
        output.push(secret);
        if output.len() > MAX_MANAGER_ITEMS {
            bail!("password-manager export contains too many items");
        }
    }
    Ok(output)
}

fn export_one_password(secrets: &[PersonalSecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    export_csv(secrets, CsvFlavor::OnePassword)
}

fn export_keepass(secrets: &[PersonalSecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    export_csv(secrets, CsvFlavor::KeePass)
}

fn export_csv(secrets: &[PersonalSecret], flavor: CsvFlavor) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let mut writer = csv::Writer::from_writer(Vec::new());
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
            CsvFlavor::KeePass => writer.write_record([
                secret.title.as_str(),
                secret.username.as_deref().unwrap_or_default(),
                secret.password.as_deref().unwrap_or_default(),
                secret.urls.first().map_or("", String::as_str),
                secret.notes.as_deref().unwrap_or_default(),
            ])?,
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

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_personal_secret_round_trips_and_legacy_is_supported() {
        let secret = PersonalSecret::generic("API token".to_owned(), "needle".to_owned());
        let encoded = secret.encode().unwrap();
        let decoded = PersonalSecret::decode("wrong title", &encoded).unwrap();
        assert_eq!(decoded.title, "API token");
        assert_eq!(decoded.password.as_deref(), Some("needle"));

        let legacy = PersonalSecret::decode("Legacy", b"old value").unwrap();
        assert_eq!(legacy.title, "Legacy");
        assert_eq!(legacy.password.as_deref(), Some("old value"));

        let future = br#"{"format":"factorseal-personal-secret","version":2,"kind":"generic","title":"Future"}"#;
        assert!(PersonalSecret::decode("Future", future).is_err());
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
        let imported = import_manager(TransferFormat::BitwardenJson, source).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].folder.as_deref(), Some("Work"));
        assert_eq!(imported[0].totp.as_deref(), Some("seed"));
        assert_eq!(imported[0].custom_fields[0].value, "code");
        let exported = export_manager(TransferFormat::BitwardenJson, &imported).unwrap();
        let again = import_manager(TransferFormat::BitwardenJson, &exported).unwrap();
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
        let imported = import_manager(TransferFormat::BitwardenJson, source).unwrap();
        let exported = export_manager(TransferFormat::BitwardenJson, &imported).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&exported).unwrap();
        let item = &value["items"][0];
        assert_eq!(item["card"]["cardholderName"], "Ada");
        assert_eq!(item["fields"].as_array().unwrap().len(), 1);
        assert_eq!(item["fields"][0]["name"], "support pin");
    }

    #[test]
    fn one_password_csv_uses_official_columns() {
        let source = b"Title,Website,Username,Password,One-time password,Favorite status,Archived status,Tags,Notes\nExample,https://example.com,user,pass,seed,true,false,work,note\n";
        let imported = import_manager(TransferFormat::OnePasswordCsv, source).unwrap();
        assert_eq!(imported[0].password.as_deref(), Some("pass"));
        assert!(imported[0].favorite);
        let exported = export_manager(TransferFormat::OnePasswordCsv, &imported).unwrap();
        assert!(String::from_utf8_lossy(&exported).starts_with("Title,Website,Username"));
        let again = import_manager(TransferFormat::OnePasswordCsv, &exported).unwrap();
        assert_eq!(again[0].totp.as_deref(), Some("seed"));
    }

    #[test]
    fn keepass_csv_uses_official_columns() {
        let source = b"Account,Login Name,Password,Web Site,Comments\nExample,user,pass,https://example.com,note\n";
        let imported = import_manager(TransferFormat::KeePassCsv, source).unwrap();
        assert_eq!(imported[0].username.as_deref(), Some("user"));
        let exported = export_manager(TransferFormat::KeePassCsv, &imported).unwrap();
        assert!(String::from_utf8_lossy(&exported).starts_with("Account,Login Name"));
        let again = import_manager(TransferFormat::KeePassCsv, &exported).unwrap();
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
}

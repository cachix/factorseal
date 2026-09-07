//! Bounded, in-memory 1Password 1PUX v3 import. No ZIP paths are extracted.
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::io::{Cursor, Read as _};

pub(super) fn import(bytes: &[u8]) -> anyhow::Result<Vec<PersonalSecret>> {
    let mut archive = zip::ZipArchive::new(Cursor::new(bytes)).context("invalid 1PUX archive")?;
    if archive.len() > MAX_MANAGER_ITEMS {
        bail!("1PUX contains too many files");
    }
    let mut names = HashSet::new();
    let mut total = 0_u64;
    for index in 0..archive.len() {
        let file = archive.by_index(index)?;
        if !names.insert(file.name().to_owned()) {
            bail!("1PUX contains duplicate file names");
        }
        total = total
            .checked_add(file.size())
            .ok_or_else(|| anyhow!("1PUX is too large"))?;
        if total > MAX_MANAGER_FILE_BYTES as u64 {
            bail!("expanded 1PUX is larger than 128 MiB");
        }
    }
    let attrs = SensitiveJson(serde_json::from_slice(&read_file(
        &mut archive,
        "export.attributes",
    )?)?);
    if attrs["version"].as_u64() != Some(3) {
        bail!("unsupported 1PUX version; expected version 3");
    }
    let data = SensitiveJson(
        serde_json::from_slice(&read_file(&mut archive, "export.data")?)
            .context("invalid 1PUX data")?,
    );
    let mut output = Vec::new();
    let document_ids = names
        .iter()
        .filter_map(|name| name.strip_prefix("files/"))
        .map(|name| name.split_once("___").map_or(name, |(id, _)| id))
        .collect();
    validate_documents(&data, &document_ids)?;
    for account in array(&data, "accounts")? {
        let account_id = required(
            account.get("attrs").unwrap_or(&serde_json::Value::Null),
            "uuid",
        )?;
        for vault in array(account, "vaults")? {
            let vault_id = required(&vault["attrs"], "uuid")?;
            for source in array(vault, "items")? {
                if output.len() >= MAX_MANAGER_ITEMS {
                    bail!("1PUX contains too many items");
                }
                output.push(read_item(
                    source,
                    account_id,
                    vault_id,
                    string_at(&vault["attrs"], "name"),
                )?);
            }
        }
    }
    // Preserve files as document items, including attachments and custom icons.
    // Source item metadata retains their document IDs for association.
    for index in 0..archive.len() {
        let file = archive.by_index(index)?;
        if file.is_dir() || matches!(file.name(), "export.attributes" | "export.data") {
            continue;
        }
        if !file.name().starts_with("files/") {
            bail!("1PUX contains an unsupported archive entry");
        }
        let name = file.name().to_owned();
        drop(file);
        let content = read_file(&mut archive, &name)?;
        let mut item = PersonalSecret::new(
            PersonalSecretKind::Document,
            name.strip_prefix("files/").unwrap().into(),
        );
        item.id = format!(
            "1password-file-{}",
            hex::encode(sha2::Sha256::digest(name.as_bytes()))
        );
        item.sections.push(PersonalSection {
            id: "document".into(),
            label: "Document".into(),
            fields: vec![PersonalField::new(
                "content",
                "File",
                PersonalFieldType::Unknown("file/base64".into()),
                STANDARD.encode(&*content),
            )],
        });
        output.push(item);
        if output.len() > MAX_MANAGER_ITEMS {
            bail!("1PUX contains too many items");
        }
    }
    let mut ids = HashSet::new();
    for item in &output {
        if !ids.insert(&item.id) {
            bail!("1PUX contains duplicate item IDs");
        }
        item.encode()?;
    }
    Ok(output)
}

fn read_file(
    archive: &mut zip::ZipArchive<Cursor<&[u8]>>,
    name: &str,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let file = archive
        .by_name(name)
        .context("1PUX is missing a required file")?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_MANAGER_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MANAGER_FILE_BYTES {
        bail!("expanded 1PUX file is too large");
    }
    Ok(bytes)
}

fn array<'a>(
    object: &'a serde_json::Value,
    key: &str,
) -> anyhow::Result<&'a Vec<serde_json::Value>> {
    object
        .get(key)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("1PUX is missing its {key} array"))
}
fn required<'a>(object: &'a serde_json::Value, key: &str) -> anyhow::Result<&'a str> {
    object
        .get(key)
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| anyhow!("1PUX is missing {key}"))
}
fn category(id: &str) -> PersonalSecretKind {
    match id {
        "001" => PersonalSecretKind::Login,
        "002" => PersonalSecretKind::Card,
        "003" => PersonalSecretKind::SecureNote,
        "004" => PersonalSecretKind::Identity,
        "101" => PersonalSecretKind::BankAccount,
        "106" => PersonalSecretKind::Passport,
        "006" => PersonalSecretKind::Document,
        "112" => PersonalSecretKind::ApiCredential,
        "114" => PersonalSecretKind::SshKey,
        _ => PersonalSecretKind::Generic,
    }
}
fn typed_value(value: &serde_json::Value) -> (PersonalFieldType, serde_json::Value) {
    use PersonalFieldType as T;
    if let Some(object) = value.as_object()
        && object.len() == 1
    {
        let (key, inner) = object.iter().next().unwrap();
        let ty = match key.as_str() {
            "string" => T::Text,
            "concealed" => T::Concealed,
            "email" => T::Email,
            "url" => T::Url,
            "phone" => T::Phone,
            "totp" => T::Totp,
            "date" => T::Date,
            "monthYear" => T::MonthYear,
            "creditCardNumber" => T::CardNumber,
            "address" => T::Address,
            "sshKey" => T::SshKey,
            "reference" => T::Reference,
            _ => T::Unknown(key.clone()),
        };
        // Preserve unexpected structured values without coercing them to strings.
        if inner.is_string()
            || matches!(
                ty,
                T::Address | T::Reference | T::Unknown(_) | T::SshKey | T::Email
            )
            || (inner.is_number() && matches!(ty, T::Date | T::MonthYear))
        {
            return (ty, inner.clone());
        }
    }
    (T::Unknown("1password-value".into()), value.clone())
}

fn validate_documents(value: &serde_json::Value, names: &HashSet<&str>) -> anyhow::Result<()> {
    match value {
        serde_json::Value::Object(object) => {
            if let Some(id) = object.get("documentId").and_then(serde_json::Value::as_str)
                && !names.contains(id)
            {
                bail!("1PUX is missing a referenced document or attachment");
            }
            for child in object.values() {
                validate_documents(child, names)?;
            }
        }
        serde_json::Value::Array(array) => {
            for child in array {
                validate_documents(child, names)?;
            }
        }
        _ => {}
    }
    Ok(())
}
use sha2::Digest as _;

#[allow(clippy::too_many_lines)]
fn read_item(
    source: &serde_json::Value,
    account_id: &str,
    vault_id: &str,
    folder: Option<String>,
) -> anyhow::Result<PersonalSecret> {
    let id = required(source, "uuid")?;
    let mut item = PersonalSecret::new(
        category(source["categoryUuid"].as_str().unwrap_or_default()),
        required(&source["overview"], "title")?.into(),
    );
    // 1Password item IDs are only unique within a vault.
    item.id = format!("1password-{account_id}-{vault_id}-{id}");
    item.folder = folder;
    item.favorite = source["favIndex"].as_u64().unwrap_or(0) > 0;
    item.archived = source["state"].as_str() == Some("archived");
    item.tags = source["overview"]["tags"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(str::to_owned))
        .collect();
    item.notes = string_at(&source["details"], "notesPlain");
    // Preserve history, source category/IDs, and properties not understood by this version.
    item.source = Some(serde_json::json!({"format":"1password-1pux", "item":source}));
    let mut account_section = PersonalSection {
        id: "account".into(),
        label: "Account".into(),
        fields: Vec::new(),
    };
    if let Some(password) = string_at(&source["details"], "password") {
        account_section.fields.push(PersonalField::new(
            "password",
            "Password",
            PersonalFieldType::Concealed,
            password,
        ));
    }
    for (index, field) in source["details"]["loginFields"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let ty = match field["fieldType"]
            .as_str()
            .or_else(|| field["type"].as_str())
            .unwrap_or("T")
        {
            "P" => PersonalFieldType::Concealed,
            "E" => PersonalFieldType::Email,
            "U" => PersonalFieldType::Url,
            "TEL" => PersonalFieldType::Phone,
            "A" => PersonalFieldType::Multiline,
            _ => PersonalFieldType::Text,
        };
        let ty = if field["designation"].as_str() == Some("password") {
            PersonalFieldType::Concealed
        } else {
            ty
        };
        account_section.fields.push(PersonalField::new(
            format!("login-{index}"),
            field["designation"]
                .as_str()
                .or_else(|| field["name"].as_str())
                .unwrap_or("Field"),
            ty,
            field["value"]
                .as_str()
                .ok_or_else(|| anyhow!("1PUX login field is not text"))?,
        ));
    }
    let urls = source["overview"]["urls"].as_array();
    for (index, url) in urls.into_iter().flatten().enumerate() {
        account_section.fields.push(PersonalField::new(
            format!("url-{index}"),
            url["label"]
                .as_str()
                .filter(|s| !s.is_empty())
                .unwrap_or("Website"),
            PersonalFieldType::Url,
            required(url, "url")?,
        ));
    }
    if urls.is_none_or(Vec::is_empty)
        && let Some(url) = string_at(&source["overview"], "url")
    {
        account_section.fields.push(PersonalField::new(
            "url-0",
            "Website",
            PersonalFieldType::Url,
            url,
        ));
    }
    if !account_section.fields.is_empty() {
        item.sections.push(account_section);
    }
    for (section_index, section) in source["details"]["sections"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let mut group = PersonalSection {
            id: format!("section-{section_index}"),
            label: section["title"].as_str().unwrap_or_default().into(),
            fields: Vec::new(),
        };
        for (index, field) in section["fields"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let value = field
                .get("value")
                .ok_or_else(|| anyhow!("1PUX field has no value"))?;
            let (ty, value) = typed_value(value);
            let mut mapped = PersonalField::new(
                format!("field-{index}"),
                field["title"].as_str().unwrap_or_default(),
                ty,
                value,
            );
            mapped.concealed |= field["guarded"].as_bool().unwrap_or(false);
            group.fields.push(mapped);
        }
        item.sections.push(group);
    }

    Ok(item)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    fn archive(version: u64, data: &serde_json::Value, files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("export.attributes", options).unwrap();
        write!(zip, "{{\"version\":{version}}}").unwrap();
        zip.start_file("export.data", options).unwrap();
        serde_json::to_writer(&mut zip, data).unwrap();
        for (name, bytes) in files {
            zip.start_file(*name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap().into_inner()
    }
    fn data() -> serde_json::Value {
        serde_json::json!({"accounts":[{"attrs":{"uuid":"account"},"vaults":[{"attrs":{"uuid":"vault","name":"Home"},"items":[{
            "uuid":"item", "categoryUuid":"001", "favIndex":1, "state":"archived",
            "overview":{"title":"Example", "urls":[{"label":"Work","url":"https://example.test"}], "tags":["work"]},
            "details":{"notesPlain":"first\nsecond", "loginFields":[{"designation":"password","fieldType":"P","value":"secret"}],
                "sections":[{"name":"recovery","title":"Recovery","fields":[
                    {"id":"same","title":"Code","value":{"concealed":"001"}},
                    {"id":"same","title":"Code","value":{"future":{"nested":"secret"}}}
                ]}], "passwordHistory":[{"value":"old-password","time":123}]}
        }]}]}]})
    }
    #[test]
    fn imports_sections_duplicate_source_ids_history_and_files() {
        let bytes = archive(3, &data(), &[("files/doc___photo.bin", &[0, 1, 255])]);
        let items = import_manager(TransferFormat::OnePasswordPux, &bytes).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].id, "1password-account-vault-item");
        assert!(items[0].favorite && items[0].archived);
        assert_eq!(items[0].sections[1].label, "Recovery");
        assert_eq!(items[0].sections[1].fields[0].text(), Some("001"));
        assert_ne!(
            items[0].sections[1].fields[0].id,
            items[0].sections[1].fields[1].id
        );
        assert_eq!(items[0].sections[1].fields[1].value["nested"], "secret");
        assert_eq!(
            items[0].source.as_ref().unwrap()["item"]["details"]["passwordHistory"][0]["value"],
            "old-password"
        );
        assert_eq!(
            STANDARD
                .decode(items[1].sections[0].fields[0].text().unwrap())
                .unwrap(),
            [0, 1, 255]
        );
        for item in items {
            assert_eq!(
                item,
                PersonalSecret::decode("", &item.encode().unwrap()).unwrap()
            );
        }
    }
    #[test]
    fn rejects_malformed_archives_versions_and_missing_data() {
        assert!(import(b"not a ZIP").is_err());
        assert!(import(&archive(4, &data(), &[])).is_err());
        assert!(import(&archive(3, &serde_json::json!({}), &[])).is_err());
        assert!(import(&archive(3, &data(), &[("unexpected", b"secret")])).is_err());
        let mut malformed = data();
        malformed["accounts"][0]["vaults"][0]["items"][0]["details"]["loginFields"][0]["value"] =
            serde_json::json!({"secret":true});
        assert!(import(&archive(3, &malformed, &[])).is_err());
        let mut missing_file = data();
        missing_file["accounts"][0]["vaults"][0]["items"][0]["details"]["documentAttributes"] =
            serde_json::json!({"documentId":"missing"});
        assert!(
            import(&archive(3, &missing_file, &[]))
                .unwrap_err()
                .to_string()
                .contains("missing a referenced")
        );
    }

    #[test]
    fn date_and_unknown_category_values_are_preserved() {
        assert_eq!(
            typed_value(&serde_json::json!({"date":123_456})),
            (PersonalFieldType::Date, serde_json::json!(123_456))
        );
        assert_eq!(category("101"), PersonalSecretKind::BankAccount);
        assert_eq!(category("106"), PersonalSecretKind::Passport);
        assert_eq!(category("006"), PersonalSecretKind::Document);
        assert_eq!(category("unknown"), PersonalSecretKind::Generic);
    }
    #[test]
    fn duplicate_item_ids_are_rejected_but_same_id_in_different_vaults_is_valid() {
        let mut source = data();
        let item = source["accounts"][0]["vaults"][0]["items"][0].clone();
        source["accounts"][0]["vaults"][0]["items"]
            .as_array_mut()
            .unwrap()
            .push(item);
        assert!(import(&archive(3, &source, &[])).is_err());
        let mut source = data();
        let mut vault = source["accounts"][0]["vaults"][0].clone();
        vault["attrs"]["uuid"] = "other".into();
        source["accounts"][0]["vaults"]
            .as_array_mut()
            .unwrap()
            .push(vault);
        let items = import(&archive(3, &source, &[])).unwrap();
        assert_ne!(items[0].id, items[1].id);
    }
}

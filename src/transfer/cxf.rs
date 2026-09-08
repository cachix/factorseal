//! CXF 1.0 (March 2026 errata) and an age v1 encrypted file transport.
//!
//! JSON functions are for in-memory interchange. File callers must encrypt it;
//! this is not an implementation of CXP or a platform credential-picker API.

use std::io::{Read as _, Write as _};

use anyhow::{Context as _, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{MAX_MANAGER_FILE_BYTES, MAX_MANAGER_ITEMS, SensitiveJson};
use crate::personal::{
    PersonalField, PersonalFieldType, PersonalSecret, PersonalSecretKind, PersonalSection,
};

mod hybrid;
mod roundtrip;
#[cfg(test)]
mod tests;
mod totp;
pub use hybrid::{HybridIdentity, HybridRecipient, read_identity_file, read_recipient_file};

const FIELD_EXTENSION: &str = "org.factorseal.field";
const ITEM_EXTENSION: &str = "org.factorseal.item";
#[cfg(not(test))]
const SCRYPT_WORK_FACTOR: u8 = 17;
#[cfg(test)]
const SCRYPT_WORK_FACTOR: u8 = 10;

/// Encrypt a CXF JSON payload as a standard binary age v1 file.
pub fn encrypt(bytes: &[u8], passphrase: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if bytes.len() > MAX_MANAGER_FILE_BYTES {
        bail!("CXF payload is larger than 128 MiB");
    }
    let mut recipient = age::scrypt::Recipient::new(secret_passphrase(passphrase)?);
    recipient.set_work_factor(SCRYPT_WORK_FACTOR);
    encrypt_with_recipient(bytes, &recipient)
}

/// Encrypt to one standard age ML-KEM-768 + X25519 hybrid public key.
pub fn encrypt_to_recipient(
    bytes: &[u8],
    recipient: &HybridRecipient,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    encrypt_with_recipient(bytes, recipient)
}

fn encrypt_with_recipient(
    bytes: &[u8],
    recipient: &dyn age::Recipient,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if bytes.len() > MAX_MANAGER_FILE_BYTES {
        bail!("CXF payload is larger than 128 MiB");
    }
    let encryptor = age::Encryptor::with_recipients(std::iter::once(recipient))?;
    let mut output = Zeroizing::new(Vec::new());
    let mut writer = encryptor.wrap_output(&mut *output)?;
    writer.write_all(bytes)?;
    writer.finish()?;
    Ok(output)
}

/// Authenticate the entire file before returning any plaintext to an importer.
pub fn decrypt(bytes: &[u8], passphrase: &[u8]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if bytes.len() as u64 > super::MAX_TRANSFER_FILE_BYTES {
        bail!("encrypted CXF file is too large");
    }
    let mut identity = age::scrypt::Identity::new(secret_passphrase(passphrase)?);
    // Bound attacker-controlled scrypt parameters to 256 MiB (r=8).
    identity.set_max_work_factor(18);
    decrypt_with_identity(bytes, &identity)
}

/// Authenticate and decrypt an age hybrid export with its private identity.
pub fn decrypt_with_hybrid_identity(
    bytes: &[u8],
    identity: &HybridIdentity,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    decrypt_with_identity(bytes, identity)
}

fn decrypt_with_identity(
    bytes: &[u8],
    identity: &dyn age::Identity,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if bytes.len() as u64 > super::MAX_TRANSFER_FILE_BYTES {
        bail!("encrypted CXF file is too large");
    }
    let decryptor = age::Decryptor::new(bytes).context("invalid age-encrypted CXF file")?;
    let reader = decryptor
        .decrypt(std::iter::once(identity))
        .context(
            "cannot decrypt CXF: incorrect passphrase or identity, unsupported work factor, or damaged file",
        )?;
    let mut output = Zeroizing::new(Vec::new());
    reader
        .take((MAX_MANAGER_FILE_BYTES + 1) as u64)
        .read_to_end(&mut output)
        .context("damaged or truncated encrypted CXF file")?;
    if output.len() > MAX_MANAGER_FILE_BYTES {
        bail!("CXF payload is larger than 128 MiB");
    }
    Ok(output)
}

fn secret_passphrase(bytes: &[u8]) -> anyhow::Result<age::secrecy::SecretString> {
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        bail!("CXF passphrase must contain 1 to 65536 UTF-8 bytes");
    }
    Ok(std::str::from_utf8(bytes)
        .context("CXF passphrase must be UTF-8")?
        .to_owned()
        .into())
}

/// Encode credentials using CXF, without an encryption envelope.
///
/// The returned bytes contain secrets. Encrypt them before writing a file.
pub fn export_json(secrets: &[PersonalSecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    roundtrip::export(secrets)
}

fn export_native_json(secrets: &[PersonalSecret]) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    if secrets.len() > MAX_MANAGER_ITEMS {
        bail!("too many CXF items");
    }
    let mut root = SensitiveJson(json!({
        "version":{"major":1,"minor":0},
        "exporterRpId":"factorseal.local",
        "exporterDisplayName":"FactorSeal",
        "timestamp":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs(),
        "accounts":[{"id":URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes()),"username":"","email":"","collections":[],"items":[]}]
    }));
    let items = root.0["accounts"][0]["items"]
        .as_array_mut()
        .context("invalid generated CXF account")?;
    let mut ids = std::collections::HashSet::new();
    for (index, secret) in secrets.iter().enumerate() {
        secret.encode()?;
        if secret.source.is_some() {
            bail!(
                "CXF item {} has unmapped source metadata; use a FactorSeal archive to preserve it",
                index + 1
            );
        }
        if !ids.insert(&secret.id) {
            bail!("duplicate personal-item ID in CXF export");
        }
        items.push(
            export_item(secret)
                .map_err(|e| anyhow::anyhow!("cannot export CXF item {}: {e}", index + 1))?,
        );
    }
    let bytes = serde_json::to_vec_pretty(&root.0).map(Zeroizing::new)?;
    if bytes.len() > MAX_MANAGER_FILE_BYTES {
        bail!("CXF payload is larger than 128 MiB");
    }
    Ok(bytes)
}

fn export_item(secret: &PersonalSecret) -> anyhow::Result<Value> {
    let mut item = SensitiveJson(json!({
        "id":identifier("item", &secret.id), "title":secret.title,
        "credentials":[],
        "extensions":[{"name":ITEM_EXTENSION,"version":1,"id":secret.id,
            "kind":secret.kind,"archived":secret.archived,"folder":secret.folder,
            "sections":secret.sections.iter().map(|s| json!({"id":s.id,"label":s.label,"fields":s.fields.iter().map(|f| &f.id).collect::<Vec<_>>()})).collect::<Vec<_>>()}]
    }));
    if secret.favorite {
        item.0["favorite"] = true.into();
    }
    if !secret.tags.is_empty() {
        item.0["tags"] = json!(secret.tags);
    }
    let credentials = item.0["credentials"]
        .as_array_mut()
        .expect("constructed array");
    let mut totp_fields = SensitiveJson(json!([]));
    for section in &secret.sections {
        let mut custom = SensitiveJson(
            json!({"type":"custom-fields","id":identifier(&secret.id, &section.id),"label":section.label,"fields":[]}),
        );
        let mut primary = std::collections::BTreeMap::new();
        for field in &section.fields {
            if field.field_type == PersonalFieldType::Totp
                && field.text().is_some_and(|s| !s.is_empty())
            {
                let encoded = SensitiveJson(export_field(field, section, &secret.id)?);
                totp_fields
                    .0
                    .as_array_mut()
                    .expect("array")
                    .push(json!({"index":credentials.len(),"field":without(&encoded,"value")?}));
                credentials.push(totp::export(field.text().context("invalid TOTP value")?)?);
                continue;
            }
            let encoded = export_field(field, section, &secret.id)?;
            if let Some((ty, key)) = primary_field(secret.kind, field) {
                let credential = primary
                    .entry(ty)
                    .or_insert_with(|| SensitiveJson(json!({"type":ty})));
                if credential.0.get(key).is_none() {
                    credential.0[key] = encoded;
                    continue;
                }
            }
            custom.0["fields"]
                .as_array_mut()
                .expect("constructed array")
                .push(encoded);
        }
        for credential in primary.values_mut() {
            credentials.push(credential.0.take());
        }
        // Keep empty sections as well: empty required fields arrays are valid CXF.
        credentials.push(custom.0.take());
    }
    if let Some(notes) = &secret.notes {
        credentials.push(json!({"type":"note","content":{"fieldType":"string","value":notes}}));
    }
    if !totp_fields.0.as_array().expect("array").is_empty() {
        item.0["extensions"][0]["totpFields"] = totp_fields.0.take();
    }
    let urls: Vec<_> = secret
        .sections
        .iter()
        .flat_map(|s| &s.fields)
        .filter(|f| f.field_type == PersonalFieldType::Url)
        .filter_map(PersonalField::text)
        .filter(|s| !s.is_empty())
        .collect();
    if !urls.is_empty() {
        item.0["scope"] = json!({"urls":urls,"androidApps":[]});
    }
    Ok(item.0.take())
}

fn primary_field(
    kind: PersonalSecretKind,
    field: &PersonalField,
) -> Option<(&'static str, &'static str)> {
    use PersonalFieldType as T;
    use PersonalSecretKind as K;
    Some(match (kind, field.id.as_str(), &field.field_type) {
        (K::Login, "username", T::Text) => ("basic-auth", "username"),
        (K::Login, "password", T::Concealed) => ("basic-auth", "password"),
        (K::ApiCredential, "token" | "key", T::Concealed) => ("api-key", "key"),
        (K::ApiCredential, "username", T::Text) => ("api-key", "username"),
        (K::ApiCredential, "url", T::Url | T::Text) => ("api-key", "url"),
        (K::Card, "cardholderName" | "fullName", T::Text) => ("credit-card", "fullName"),
        (K::Card, "number", T::CardNumber | T::Concealed) => ("credit-card", "number"),
        (K::Card, "code" | "verificationNumber", T::Concealed) => {
            ("credit-card", "verificationNumber")
        }
        (K::Identity, "firstName" | "given", T::Text) => ("person-name", "given"),
        (K::Identity, "lastName" | "surname", T::Text) => ("person-name", "surname"),
        (K::SecureNote, "note", T::Multiline) => ("note", "content"),
        _ => return None,
    })
}

fn export_field(
    field: &PersonalField,
    section: &PersonalSection,
    item_id: &str,
) -> anyhow::Result<Value> {
    let ty = if field.concealed {
        "concealed-string"
    } else {
        match field.field_type {
            PersonalFieldType::Boolean
                if field.value.is_boolean() || matches!(field.text(), Some("true" | "false")) =>
            {
                "boolean"
            }
            PersonalFieldType::Email => "email",
            // Native dates may be empty or use a vendor-specific spelling.
            // Keep those strings intact; the extension retains their native type.
            _ => "string",
        }
    };
    let value = Zeroizing::new(match &field.value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        _ => bail!(
            "structured or numeric fields cannot yet be exported to CXF; use a FactorSeal archive"
        ),
    });
    if matches!(field.field_type, PersonalFieldType::Unknown(_)) {
        bail!("unrecognized fields cannot yet be exported to CXF; use a FactorSeal archive");
    }
    Ok(
        json!({"id":identifier(&identifier(item_id, &section.id), &field.id),"label":field.label,"fieldType":ty,"value":value.as_str(),
        "extensions":[{"name":FIELD_EXTENSION,"version":1,"id":field.id,
            "fieldType":field.field_type,"concealed":field.concealed,
            "booleanValue":field.value.is_boolean(),"sectionId":section.id,"sectionLabel":section.label}]}),
    )
}

/// Read a CXF 1.0 JSON header. Unknown data is retained as encrypted source
/// metadata; it is never interpreted as a working authentication capability.
pub fn import_json(bytes: &[u8]) -> anyhow::Result<Vec<PersonalSecret>> {
    if bytes.len() > MAX_MANAGER_FILE_BYTES {
        bail!("CXF payload is larger than 128 MiB");
    }
    let root = SensitiveJson(serde_json::from_slice(bytes).context("invalid CXF JSON")?);
    if root["version"]["major"].as_u64() != Some(1) || root["version"]["minor"].as_u64() != Some(0)
    {
        bail!("unsupported CXF version; expected 1.0");
    }
    text(&root, "exporterRpId")?;
    text(&root, "exporterDisplayName")?;
    root["timestamp"]
        .as_u64()
        .context("invalid CXF timestamp")?;
    let accounts = array(&root, "accounts")?;
    let mut output = Vec::new();
    let mut account_ids = std::collections::HashSet::new();
    for account in accounts {
        let account_id = valid_id(account, "id")?;
        if !account_ids.insert(account_id.clone()) {
            bail!("duplicate CXF account ID");
        }
        text(account, "username")?;
        text(account, "email")?;
        let collections = array(account, "collections")?;
        let items = array(account, "items")?;
        if items.is_empty()
            && (!collections.is_empty()
                || !text(account, "username")?.is_empty()
                || !text(account, "email")?.is_empty()
                || has_unknown(
                    account,
                    &["id", "username", "email", "collections", "items"],
                ))
        {
            bail!(
                "CXF contains an empty account with metadata that cannot be stored without an item; no items were imported"
            );
        }
        if output.len().saturating_add(items.len()) > MAX_MANAGER_ITEMS {
            bail!("too many CXF items");
        }
        let mut ids = std::collections::HashSet::new();
        for (index, original) in items.iter().enumerate() {
            let id = valid_id(original, "id")?;
            if !ids.insert(id.clone()) {
                bail!("duplicate CXF item ID");
            }
            let (mut item, bindings) = import_item(original, &account_id, &id)
                .map_err(|e| anyhow::anyhow!("invalid CXF item {}: {e}", index + 1))?;
            // Collections, account attributes and future header fields are retained
            // when they cannot be mapped, instead of quietly discarded.
            if extension(original, ITEM_EXTENSION)?.is_none_or(|meta| meta["version"] == 2)
                || item.source.is_some()
                || !collections.is_empty()
                || account["username"].as_str().is_some_and(|s| !s.is_empty())
                || account["email"].as_str().is_some_and(|s| !s.is_empty())
                || account.get("fullName").is_some()
                || account.get("extensions").is_some()
                || has_unknown(
                    account,
                    &[
                        "id",
                        "username",
                        "email",
                        "fullName",
                        "collections",
                        "items",
                    ],
                )
                || has_unknown(
                    &root,
                    &[
                        "version",
                        "exporterRpId",
                        "exporterDisplayName",
                        "timestamp",
                        "accounts",
                    ],
                )
            {
                let metadata = SensitiveJson(without(account, "items")?);
                let header = SensitiveJson(without(&root, "accounts")?);
                let unsupported = item.source.is_some();
                if let Some(source) = &mut item.source {
                    crate::personal::zeroize_json_strings(source);
                }
                item.source = Some(
                    json!({"format":"cxf","item":original,"account":metadata.0,"header":header.0,"bindings":bindings,"unsupported":unsupported}),
                );
            }
            // Preparation must fail before a live vault write if any item is too large.
            item.encode()?;
            output.push(item);
        }
    }
    Ok(output)
}

#[allow(clippy::too_many_lines)]
fn import_item(
    original: &Value,
    account_id: &[u8],
    id: &[u8],
) -> anyhow::Result<(PersonalSecret, Vec<roundtrip::Binding>)> {
    let mut bindings = Vec::new();
    let mut item = PersonalSecret::new(
        PersonalSecretKind::Generic,
        text(original, "title")?.to_owned(),
    );
    let mut digest = Sha256::new();
    digest.update(b"factorseal/cxf-item/v1\0");
    digest.update((account_id.len() as u64).to_be_bytes());
    digest.update(account_id);
    digest.update(id);
    item.id = format!("cxf-{}", hex::encode(digest.finalize()));
    if let Some(v) = original.get("favorite") {
        item.favorite = v.as_bool().context("invalid CXF favorite")?;
    }
    if let Some(tags) = original.get("tags") {
        item.tags = tags
            .as_array()
            .context("invalid CXF tags")?
            .iter()
            .map(|v| v.as_str().map(str::to_owned).context("invalid CXF tag"))
            .collect::<anyhow::Result<_>>()?;
    }
    let mut unmapped = has_unknown(
        original,
        &[
            "id",
            "title",
            "favorite",
            "credentials",
            "tags",
            "scope",
            "extensions",
        ],
    );
    let native = extension(original, ITEM_EXTENSION)?;
    if let Some(meta) = native {
        unmapped |= has_unknown(
            meta,
            &[
                "name",
                "version",
                "id",
                "kind",
                "archived",
                "folder",
                "sections",
                "totpFields",
                "opaqueFields",
            ],
        );
        if meta["version"] != 1 && meta["version"] != 2 {
            bail!("unsupported FactorSeal CXF item extension");
        }
        item.kind =
            serde_json::from_value(meta["kind"].clone()).context("invalid CXF item kind")?;
        item.archived = meta["archived"]
            .as_bool()
            .context("invalid CXF archived flag")?;
        item.folder = match &meta["folder"] {
            Value::Null => None,
            Value::String(s) => Some(s.clone()),
            _ => bail!("invalid CXF folder"),
        };
        // Only restore a native ID when it matches the standard item's identity.
        let native_id = text(meta, "id")?;
        let identity_matches = if meta["version"] == 1 {
            decode_id(&identifier("item", native_id))? == id
        } else {
            // Version 2 retains a foreign item's standard account/item IDs.
            // The local ID must be their deterministic projection.
            native_id == item.id
        };
        if !identity_matches {
            bail!("inconsistent CXF item ID");
        }
        native_id.clone_into(&mut item.id);
        if let Some(sections) = meta.get("sections") {
            for section in sections.as_array().context("invalid CXF section order")? {
                let id = text(section, "id")?;
                if item.sections.iter().any(|s| s.id == id) {
                    bail!("duplicate CXF section identity");
                }
                item.sections.push(PersonalSection {
                    id: id.into(),
                    label: text(section, "label")?.into(),
                    fields: Vec::new(),
                });
            }
        }
    }
    unmapped |= other_extensions(original, ITEM_EXTENSION)?;
    for (index, credential) in array(original, "credentials")?.iter().enumerate() {
        let ty = text(credential, "type")?;
        let section_id = format!("cxf-{index}");
        match ty {
            "custom-fields" => {
                let label = credential
                    .get("label")
                    .map(|v| v.as_str().context("invalid CXF section label"))
                    .transpose()?
                    .unwrap_or("Custom fields");
                if let Some(id) = credential.get("id") {
                    decode_id(id.as_str().context("invalid CXF section ID")?)?;
                }
                for (field_index, field) in array(credential, "fields")?.iter().enumerate() {
                    bindings.push(roundtrip::Binding::field(
                        field,
                        &section_id,
                        &format!("field-{field_index}"),
                        format!("/credentials/{index}/fields/{field_index}"),
                    )?);
                    unmapped |= import_field(
                        &mut item,
                        field,
                        &section_id,
                        label,
                        &format!("field-{field_index}"),
                    )?;
                }
                unmapped |= has_unknown(credential, &["type", "id", "label", "fields"]);
            }
            "basic-auth" | "api-key" | "credit-card" | "person-name" | "address" | "passport"
            | "identity-document" | "drivers-license" | "wifi" => {
                if native.is_none() {
                    item.kind = credential_kind(ty);
                }
                for (key, field) in credential.as_object().context("invalid CXF credential")? {
                    if key == "type" {
                        continue;
                    }
                    if field.get("fieldType").is_some() {
                        bindings.push(roundtrip::Binding::field(
                            field,
                            &section_id,
                            key,
                            format!("/credentials/{index}/{}", roundtrip::escape(key)),
                        )?);
                        unmapped |= import_field(&mut item, field, &section_id, ty, key)?;
                    } else {
                        unmapped = true;
                    }
                }
            }
            "note" => {
                let content = &credential["content"];
                if item.notes.is_none()
                    && content["fieldType"] == "string"
                    && !has_unknown(content, &["fieldType", "value"])
                {
                    item.notes = Some(text(content, "value")?.to_owned());
                    bindings.push(roundtrip::Binding::note(index));
                } else {
                    bindings.push(roundtrip::Binding::field(
                        content,
                        &section_id,
                        "note",
                        format!("/credentials/{index}/content"),
                    )?);
                    unmapped |= import_field(&mut item, content, &section_id, "Note", "note")?;
                }
                unmapped |= has_unknown(credential, &["type", "content"]);
            }
            "generated-password" => {
                let field =
                    json!({"fieldType":"concealed-string","value":text(credential,"password")?});
                let field = SensitiveJson(field);
                bindings.push(roundtrip::Binding::value(
                    &section_id,
                    "password",
                    format!("/credentials/{index}/password"),
                ));
                import_field(&mut item, &field, &section_id, "Password", "password")?;
                unmapped |= has_unknown(credential, &["type", "password"]);
            }
            "totp" => {
                let uri = totp::import(credential)?;
                if let Some(meta) = totp::field_metadata(native, index)? {
                    let mut field = SensitiveJson(meta["field"].clone());
                    field.0["value"] = uri.as_str().into();
                    bindings.push(roundtrip::Binding::totp(Some(&field), &section_id, index)?);
                    unmapped |=
                        import_field(&mut item, &field, &section_id, "Verification code", "totp")?;
                } else {
                    bindings.push(roundtrip::Binding::totp(None, &section_id, index)?);
                    push_field(
                        &mut item,
                        &section_id,
                        "Verification code",
                        PersonalField::new(
                            "totp",
                            "One-time password",
                            PersonalFieldType::Totp,
                            uri.as_str(),
                        ),
                    )?;
                }
                unmapped |= has_unknown(
                    credential,
                    &[
                        "type",
                        "secret",
                        "period",
                        "digits",
                        "algorithm",
                        "username",
                        "issuer",
                    ],
                );
            }
            "file" => {
                bail!("CXF file references require an attachment transport; no items were imported")
            }
            _ => {
                let projection = native
                    .filter(|meta| meta.get("opaqueFields").is_some())
                    .map(|meta| array(meta, "opaqueFields"))
                    .transpose()?
                    .and_then(|fields| fields.iter().find(|meta| meta["index"] == index));
                let section_id = projection
                    .map(|meta| text(meta, "sectionId"))
                    .transpose()?
                    .unwrap_or(&section_id);
                let section_label = projection
                    .map(|meta| text(meta, "sectionLabel"))
                    .transpose()?
                    .unwrap_or(ty);
                let field_id = projection
                    .map(|meta| text(meta, "id"))
                    .transpose()?
                    .unwrap_or("credential");
                let field_label = projection
                    .map(|meta| text(meta, "label"))
                    .transpose()?
                    .unwrap_or(ty);
                bindings.push(roundtrip::Binding::opaque(section_id, field_id, index));
                // Includes passkeys: retain all bytes without claiming authentication support.
                push_field(
                    &mut item,
                    section_id,
                    section_label,
                    PersonalField::new(
                        field_id,
                        field_label,
                        PersonalFieldType::Unknown(format!("cxf-{ty}")),
                        credential.clone(),
                    ),
                )?;
                unmapped = true;
            }
        }
    }
    if let Some(scope) = original.get("scope") {
        let urls = array(scope, "urls")?;
        let android = array(scope, "androidApps")?;
        for (index, url) in urls.iter().enumerate() {
            let url = url.as_str().context("invalid CXF URL")?;
            let exists = item
                .sections
                .iter()
                .flat_map(|s| &s.fields)
                .any(|f| f.field_type == PersonalFieldType::Url && f.text() == Some(url));
            if !exists {
                bindings.push(roundtrip::Binding::value(
                    "cxf-scope",
                    &format!("url-{index}"),
                    format!("/scope/urls/{index}"),
                ));
                push_field(
                    &mut item,
                    "cxf-scope",
                    "Websites",
                    PersonalField::new(
                        format!("url-{index}"),
                        "Website",
                        PersonalFieldType::Url,
                        url,
                    ),
                )?;
            }
        }
        unmapped |= !android.is_empty() || has_unknown(scope, &["urls", "androidApps"]);
    }
    if let Some(sections) = native
        .and_then(|m| m.get("sections"))
        .and_then(Value::as_array)
    {
        for section in &mut item.sections {
            if let Some(order) = sections.iter().find(|s| s["id"] == section.id) {
                let ids = array(order, "fields")?;
                section.fields.sort_by_key(|f| {
                    ids.iter()
                        .position(|id| id.as_str() == Some(&f.id))
                        .unwrap_or(usize::MAX)
                });
            }
        }
    }
    if !item.has_storage_id() {
        bail!("invalid CXF storage ID");
    }
    if unmapped {
        item.source = Some(json!({"format":"cxf","item":original}));
    }
    Ok((item, bindings))
}

fn import_field(
    item: &mut PersonalSecret,
    field: &Value,
    section_id: &str,
    section_label: &str,
    default_id: &str,
) -> anyhow::Result<bool> {
    let ty = text(field, "fieldType")?;
    let value = text(field, "value")?;
    if let Some(id) = field.get("id") {
        decode_id(id.as_str().context("invalid CXF field ID")?)?;
    }
    let label = field
        .get("label")
        .map(|v| v.as_str().context("invalid CXF field label"))
        .transpose()?
        .unwrap_or(default_id);
    let field_type = match ty {
        "string"
        | "number"
        | "country-code"
        | "subdivision-code"
        | "wifi-network-security-type" => PersonalFieldType::Text,
        "concealed-string" => PersonalFieldType::Concealed,
        "email" => PersonalFieldType::Email,
        "boolean" => PersonalFieldType::Boolean,
        "date" => PersonalFieldType::Date,
        "year-month" => PersonalFieldType::MonthYear,
        _ => PersonalFieldType::Unknown(format!("cxf-{ty}")),
    };
    let mut result = PersonalField::new(default_id, label, field_type, value);
    let sensitive_role = matches!(
        default_id,
        "password" | "key" | "number" | "verificationNumber" | "pin" | "passphrase"
    );
    let mut unmapped_metadata = false;
    let mut sid = section_id;
    let mut slabel = section_label;
    if let Some(meta) = extension(field, FIELD_EXTENSION)? {
        unmapped_metadata = has_unknown(
            meta,
            &[
                "name",
                "version",
                "id",
                "fieldType",
                "concealed",
                "booleanValue",
                "sectionId",
                "sectionLabel",
            ],
        );
        if meta["version"] != 1 {
            bail!("unsupported FactorSeal CXF field extension");
        }
        text(meta, "id")?.clone_into(&mut result.id);
        result.field_type = serde_json::from_value(meta["fieldType"].clone())
            .context("invalid CXF field type extension")?;
        result.concealed = meta["concealed"]
            .as_bool()
            .context("invalid CXF concealment")?;
        if meta["booleanValue"] == true {
            result.value = match value {
                "true" => true.into(),
                "false" => false.into(),
                _ => bail!("invalid CXF boolean"),
            };
        }
        sid = text(meta, "sectionId")?;
        slabel = text(meta, "sectionLabel")?;
        if ty == "concealed-string" {
            result.concealed = true;
        }
    }
    if sensitive_role {
        result.concealed = true;
    }
    let unmapped = unmapped_metadata
        || matches!(result.field_type, PersonalFieldType::Unknown(_))
        || has_unknown(field, &["id", "label", "fieldType", "value", "extensions"])
        || other_extensions(field, FIELD_EXTENSION)?;
    push_field(item, sid, slabel, result)?;
    Ok(unmapped)
}

fn push_field(
    item: &mut PersonalSecret,
    id: &str,
    label: &str,
    field: PersonalField,
) -> anyhow::Result<()> {
    if let Some(section) = item.sections.iter_mut().find(|s| s.id == id) {
        if section.fields.iter().any(|f| f.id == field.id) {
            bail!("duplicate CXF field identity");
        }
        section.fields.push(field);
    } else {
        item.sections.push(PersonalSection {
            id: id.to_owned(),
            label: label.to_owned(),
            fields: vec![field],
        });
    }
    Ok(())
}

fn credential_kind(ty: &str) -> PersonalSecretKind {
    match ty {
        "basic-auth" => PersonalSecretKind::Login,
        "api-key" => PersonalSecretKind::ApiCredential,
        "credit-card" => PersonalSecretKind::Card,
        "passport" => PersonalSecretKind::Passport,
        "person-name" | "address" | "identity-document" | "drivers-license" => {
            PersonalSecretKind::Identity
        }
        _ => PersonalSecretKind::Generic,
    }
}

fn text<'a>(v: &'a Value, key: &str) -> anyhow::Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid CXF {key}"))
}

fn array<'a>(v: &'a Value, key: &str) -> anyhow::Result<&'a Vec<Value>> {
    v.get(key)
        .and_then(Value::as_array)
        .with_context(|| format!("missing or invalid CXF {key} array"))
}

fn valid_id(v: &Value, key: &str) -> anyhow::Result<Vec<u8>> {
    decode_id(text(v, key)?)
}

fn decode_id(id: &str) -> anyhow::Result<Vec<u8>> {
    if id.len() > 88 {
        bail!("CXF ID is too long");
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(id)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(id))
        .context("invalid CXF base64url ID")?;
    if bytes.is_empty() || bytes.len() > 64 {
        bail!("CXF IDs must contain 1 to 64 bytes");
    }
    Ok(bytes)
}

fn identifier(domain: &str, value: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"factorseal/cxf-id/v1\0");
    hash.update(domain);
    hash.update(b"\0");
    hash.update(value);
    URL_SAFE_NO_PAD.encode(hash.finalize())
}

fn has_unknown(v: &Value, known: &[&str]) -> bool {
    v.as_object()
        .is_some_and(|o| o.keys().any(|k| !known.contains(&k.as_str())))
}

fn without(v: &Value, key: &str) -> anyhow::Result<Value> {
    Ok(Value::Object(
        v.as_object()
            .context("invalid CXF object")?
            .iter()
            .filter(|(k, _)| k.as_str() != key)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    ))
}

fn extension<'a>(v: &'a Value, name: &str) -> anyhow::Result<Option<&'a Value>> {
    let Some(extensions) = v.get("extensions") else {
        return Ok(None);
    };
    let mut found = None;
    for e in extensions.as_array().context("invalid CXF extensions")? {
        if text(e, "name")? == name {
            if found.is_some() {
                bail!("duplicate CXF extension");
            }
            found = Some(e);
        }
    }
    Ok(found)
}

fn other_extensions(v: &Value, known: &str) -> anyhow::Result<bool> {
    let Some(extensions) = v.get("extensions") else {
        return Ok(false);
    };
    Ok(extensions
        .as_array()
        .context("invalid CXF extensions")?
        .iter()
        .any(|e| e["name"] != known))
}

//! Versioned personal items, independent of password-manager transfer formats.
use super::*;
use sha2::{Digest as _, Sha256};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PersonalFieldType {
    Text,
    Concealed,
    Url,
    Email,
    Phone,
    Date,
    MonthYear,
    Totp,
    Multiline,
    Boolean,
    CardNumber,
    SshKey,
    Address,
    Reference,
    /// Retains the source type without interpreting its value.
    Unknown(String),
}

impl PersonalFieldType {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Text => "Text",
            Self::Concealed => "Password",
            Self::Url => "Website",
            Self::Email => "Email",
            Self::Phone => "Phone",
            Self::Date => "Date",
            Self::MonthYear => "Month and year",
            Self::Totp => "One-time password",
            Self::Multiline => "Multiline text",
            Self::Boolean => "Boolean",
            Self::CardNumber => "Card number",
            Self::SshKey => "SSH key",
            Self::Address => "Address",
            Self::Reference => "Reference",
            Self::Unknown(_) => "Imported field",
        }
    }
    #[must_use]
    pub fn concealed(&self) -> bool {
        matches!(
            self,
            Self::Concealed | Self::Totp | Self::CardNumber | Self::SshKey | Self::Unknown(_)
        )
    }
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalField {
    pub id: String,
    pub label: String,
    pub field_type: PersonalFieldType,
    pub concealed: bool,
    /// JSON accommodates structured addresses, references, and unknown source types.
    pub value: serde_json::Value,
}

impl std::fmt::Debug for PersonalField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersonalField([REDACTED])")
    }
}

impl PersonalField {
    #[must_use]
    pub fn new(
        id: impl Into<String>,
        label: impl Into<String>,
        field_type: PersonalFieldType,
        value: impl Into<serde_json::Value>,
    ) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            concealed: field_type.concealed(),
            field_type,
            value: value.into(),
        }
    }

    #[must_use]
    pub fn text(&self) -> Option<&str> {
        self.value.as_str()
    }
}

impl Drop for PersonalField {
    fn drop(&mut self) {
        self.label.zeroize();
        zeroize_json_strings(&mut self.value);
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalSection {
    pub id: String,
    pub label: String,
    pub fields: Vec<PersonalField>,
}

impl Drop for PersonalSection {
    fn drop(&mut self) {
        self.label.zeroize();
    }
}

#[derive(Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalSecret {
    format: String,
    version: u16,
    pub id: String,
    pub kind: PersonalSecretKind,
    pub title: String,
    pub sections: Vec<PersonalSection>,
    #[serde(default)]
    pub notes: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub archived: bool,
    /// Original source properties that have no native equivalent, encrypted with the item.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<serde_json::Value>,
}

impl std::fmt::Debug for PersonalSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersonalSecret([REDACTED])")
    }
}

impl Drop for PersonalSecret {
    fn drop(&mut self) {
        self.title.zeroize();
        self.notes.zeroize();
        self.folder.zeroize();
        self.tags.zeroize();
        if let Some(source) = &mut self.source {
            zeroize_json_strings(source);
        }
    }
}

impl PersonalSecretKind {
    pub const ALL: [Self; 10] = [
        Self::Login,
        Self::SecureNote,
        Self::Card,
        Self::Identity,
        Self::SshKey,
        Self::ApiCredential,
        Self::Passport,
        Self::BankAccount,
        Self::Document,
        Self::Generic,
    ];

    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::SecureNote => "Secure note",
            Self::Card => "Card",
            Self::Identity => "Identity",
            Self::SshKey => "SSH key",
            Self::ApiCredential => "API credential",
            Self::Passport => "Passport",
            Self::BankAccount => "Bank account",
            Self::Document => "Document",
            Self::Generic => "Other",
        }
    }
}

impl PersonalSecret {
    #[must_use]
    pub fn new(kind: PersonalSecretKind, title: String) -> Self {
        Self {
            format: PERSONAL_FORMAT.into(),
            version: 2,
            id: uuid::Uuid::new_v4().to_string(),
            kind,
            title,
            sections: Vec::new(),
            notes: None,
            folder: None,
            tags: Vec::new(),
            favorite: false,
            archived: false,
            source: None,
        }
    }

    #[must_use]
    pub fn template(kind: PersonalSecretKind, title: String) -> Self {
        use PersonalFieldType as T;
        let fields: &[(&str, &str, T)] = match kind {
            PersonalSecretKind::Login => &[
                ("username", "Username", T::Text),
                ("password", "Password", T::Concealed),
                ("url-0", "Website", T::Url),
                ("totp", "One-time password", T::Totp),
            ],
            PersonalSecretKind::SecureNote => &[("note", "Note", T::Multiline)],
            PersonalSecretKind::Card => &[
                ("cardholderName", "Cardholder", T::Text),
                ("number", "Card number", T::CardNumber),
                ("expMonth", "Expiry month", T::Text),
                ("expYear", "Expiry year", T::Text),
                ("code", "Security code", T::Concealed),
            ],
            PersonalSecretKind::Identity => &[
                ("firstName", "First name", T::Text),
                ("lastName", "Last name", T::Text),
                ("email", "Email", T::Email),
                ("phone", "Phone", T::Phone),
            ],
            PersonalSecretKind::SshKey => &[
                ("private-key", "Private key", T::SshKey),
                ("public-key", "Public key", T::Multiline),
                ("passphrase", "Passphrase", T::Concealed),
            ],
            PersonalSecretKind::ApiCredential => &[
                ("username", "Account", T::Text),
                ("token", "Token", T::Concealed),
                ("url", "Endpoint", T::Url),
            ],
            PersonalSecretKind::Passport => &[
                ("name", "Full name", T::Text),
                ("number", "Passport number", T::Concealed),
                ("country", "Issuing country", T::Text),
                ("expiry", "Expiry date", T::Date),
            ],
            PersonalSecretKind::BankAccount => &[
                ("bank", "Bank", T::Text),
                ("account", "Account number", T::Concealed),
                ("routing", "Routing number", T::Text),
                ("iban", "IBAN", T::Concealed),
            ],
            PersonalSecretKind::Document => &[("description", "Description", T::Multiline)],
            PersonalSecretKind::Generic => &[("password", "Secret value", T::Concealed)],
        };
        let mut item = Self::new(kind, title);
        item.sections.push(PersonalSection {
            id: section_id(kind).into(),
            label: kind.label().into(),
            fields: fields
                .iter()
                .map(|(id, label, ty)| PersonalField::new(*id, *label, ty.clone(), ""))
                .collect(),
        });
        item
    }

    #[must_use]
    pub fn generic(title: String, value: String) -> Self {
        let mut item = Self::template(PersonalSecretKind::Generic, title);
        item.sections[0].fields[0].value = value.into();
        item
    }

    pub fn encode(&self) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)
            .map(Zeroizing::new)
            .context("could not encode personal item")?;
        // Leave room for base64 and request metadata inside the 1 MiB IPC envelope.
        if bytes.len() > 512 * 1024 {
            bail!("personal item exceeds the 512 KiB storage limit");
        }
        Ok(bytes)
    }

    pub fn decode(title: &str, bytes: &[u8]) -> anyhow::Result<Self> {
        if let Ok(header) = serde_json::from_slice::<PersonalHeader<'_>>(bytes)
            && header.format == Some(PERSONAL_FORMAT)
        {
            return match header.version {
                Some(1) => Self::from_legacy(LegacySecret::decode(title, bytes)?),
                Some(2) => {
                    let item: Self =
                        serde_json::from_slice(bytes).context("invalid personal item")?;
                    item.validate()?;
                    Ok(item)
                }
                _ => bail!("unsupported FactorSeal personal-secret version"),
            };
        }
        Self::from_legacy(LegacySecret::decode(title, bytes)?)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.format != PERSONAL_FORMAT || self.version != 2 || self.id.is_empty() {
            bail!("invalid personal-item format, version or ID");
        }
        let mut sections = HashSet::new();
        for section in &self.sections {
            if section.id.is_empty() || !sections.insert(&section.id) {
                bail!("duplicate or empty section ID");
            }
            let mut fields = HashSet::new();
            for field in &section.fields {
                if field.id.is_empty() || !fields.insert(&field.id) {
                    bail!("duplicate or empty field ID");
                }
                let valid = match field.field_type {
                    PersonalFieldType::Unknown(_)
                    | PersonalFieldType::SshKey
                    | PersonalFieldType::Email
                    | PersonalFieldType::Address
                    | PersonalFieldType::Reference => true,
                    PersonalFieldType::Boolean => {
                        field.value.is_boolean()
                            || matches!(field.text(), Some("true" | "false" | ""))
                    }
                    PersonalFieldType::Date | PersonalFieldType::MonthYear => {
                        field.value.is_string() || field.value.is_number()
                    }
                    _ => field.value.is_string(),
                };
                if !valid {
                    bail!("field value does not match its type");
                }
                if field.field_type.concealed() && !field.concealed {
                    bail!("sensitive field must be concealed");
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn from_legacy(mut old: LegacySecret) -> anyhow::Result<Self> {
        let bytes = old.encode()?;
        let mut item = Self::new(old.kind, std::mem::take(&mut old.title));
        item.id = format!("legacy-{}", hex::encode(Sha256::digest(&*bytes)));
        item.notes = old.notes.take();
        item.folder = old.folder.take();
        item.tags = std::mem::take(&mut old.tags);
        item.favorite = old.favorite;
        item.archived = old.archived;
        let mut account = PersonalSection {
            id: "account".into(),
            label: "Account".into(),
            fields: Vec::new(),
        };
        for (id, label, ty, value) in [
            (
                "username",
                "Username",
                PersonalFieldType::Text,
                old.username.take(),
            ),
            (
                "password",
                "Password",
                PersonalFieldType::Concealed,
                old.password.take(),
            ),
            (
                "totp",
                "One-time password",
                PersonalFieldType::Totp,
                old.totp.take(),
            ),
        ] {
            if let Some(value) = value {
                account
                    .fields
                    .push(PersonalField::new(id, label, ty, value));
            }
        }
        for (index, url) in old.urls.drain(..).enumerate() {
            account.fields.push(PersonalField::new(
                format!("url-{index}"),
                "Website",
                PersonalFieldType::Url,
                url,
            ));
        }
        if !account.fields.is_empty() {
            item.sections.push(account);
        }
        for section in [
            LegacyFieldSection::Card,
            LegacyFieldSection::Identity,
            LegacyFieldSection::Custom,
        ] {
            let id = match section {
                LegacyFieldSection::Card => "card",
                LegacyFieldSection::Identity => "identity",
                LegacyFieldSection::Custom => "custom",
            };
            let mut group = PersonalSection {
                id: id.into(),
                label: id.into(),
                fields: Vec::new(),
            };
            for (index, field) in old
                .custom_fields
                .iter_mut()
                .enumerate()
                .filter(|(_, f)| f.section == section)
            {
                let ty = if section == LegacyFieldSection::Custom {
                    match field.field_type {
                        0 => PersonalFieldType::Text,
                        1 => PersonalFieldType::Concealed,
                        2 => PersonalFieldType::Boolean,
                        3 => PersonalFieldType::Reference,
                        n => PersonalFieldType::Unknown(format!("bitwarden-{n}")),
                    }
                } else if field.name == "number" && section == LegacyFieldSection::Card {
                    PersonalFieldType::CardNumber
                } else if matches!(
                    field.name.as_str(),
                    "code" | "ssn" | "passportNumber" | "licenseNumber"
                ) {
                    PersonalFieldType::Concealed
                } else {
                    PersonalFieldType::Text
                };
                let value = if let Some(linked) = field.linked_id {
                    serde_json::json!({"linkedId": linked, "value": field.value})
                } else {
                    serde_json::Value::String(std::mem::take(&mut field.value))
                };
                group.fields.push(PersonalField::new(
                    if section == LegacyFieldSection::Custom {
                        format!("custom-{index}")
                    } else {
                        field.name.clone()
                    },
                    field.name.clone(),
                    ty,
                    value,
                ));
            }
            if !group.fields.is_empty() {
                item.sections.push(group);
            }
        }
        item.validate()?;
        Ok(item)
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn to_legacy(&self) -> anyhow::Result<LegacySecret> {
        self.validate()?;
        let loss = || {
            anyhow!(
                "this transfer format cannot preserve all fields or metadata; use an encrypted FactorSeal archive for a lossless export"
            )
        };
        if self.source.is_some()
            || !matches!(
                self.kind,
                PersonalSecretKind::Login
                    | PersonalSecretKind::Generic
                    | PersonalSecretKind::SecureNote
                    | PersonalSecretKind::Card
                    | PersonalSecretKind::Identity
            )
        {
            return Err(loss());
        }
        let mut old = LegacySecret::new(self.kind, self.title.clone());
        let template = Self::template(self.kind, String::new());
        old.notes.clone_from(&self.notes);
        old.folder.clone_from(&self.folder);
        old.tags.clone_from(&self.tags);
        old.favorite = self.favorite;
        old.archived = self.archived;
        for section in &self.sections {
            if ![section.id.as_str(), "Account", self.kind.label()]
                .contains(&section.label.as_str())
            {
                return Err(loss());
            }
            for field in &section.fields {
                if section.id == "account" {
                    let text = field.text().ok_or_else(loss)?.to_owned();
                    let expected_label = match field.id.as_str() {
                        "username" => "Username",
                        "password" if self.kind == PersonalSecretKind::Generic => "Secret value",
                        "password" => "Password",
                        "totp" => "One-time password",
                        _ => "Website",
                    };
                    if field.label != expected_label
                        && !(field.id == "password" && field.label == "Password")
                    {
                        return Err(loss());
                    }
                    match (field.id.as_str(), &field.field_type) {
                        ("username", PersonalFieldType::Text) if !field.concealed => {
                            old.username = nonempty(text);
                        }
                        ("password", PersonalFieldType::Concealed) => old.password = nonempty(text),
                        ("totp", PersonalFieldType::Totp) => old.totp = nonempty(text),
                        (id, PersonalFieldType::Url)
                            if id.starts_with("url-") && !field.concealed =>
                        {
                            if !text.is_empty() {
                                old.urls.push(text);
                            }
                        }
                        _ => return Err(loss()),
                    }
                } else {
                    let legacy_section = match section.id.as_str() {
                        "card" if self.kind == PersonalSecretKind::Card => LegacyFieldSection::Card,
                        "identity" if self.kind == PersonalSecretKind::Identity => {
                            LegacyFieldSection::Identity
                        }
                        "custom" => LegacyFieldSection::Custom,
                        _ => return Err(loss()),
                    };
                    if legacy_section != LegacyFieldSection::Custom
                        && field.label != field.id
                        && !template
                            .sections
                            .iter()
                            .flat_map(|section| &section.fields)
                            .any(|standard| {
                                standard.id == field.id && standard.label == field.label
                            })
                    {
                        return Err(loss());
                    }
                    if field.field_type == PersonalFieldType::Reference
                        && field.value.as_object().is_some_and(|object| {
                            object
                                .keys()
                                .any(|key| !["linkedId", "value"].contains(&key.as_str()))
                        })
                    {
                        return Err(loss());
                    }
                    let (ty, linked_id, value) = match &field.field_type {
                        PersonalFieldType::Text if !field.concealed => {
                            (0, None, field.text().ok_or_else(loss)?.to_owned())
                        }
                        PersonalFieldType::Concealed => {
                            (1, None, field.text().ok_or_else(loss)?.to_owned())
                        }
                        PersonalFieldType::CardNumber
                            if legacy_section == LegacyFieldSection::Card =>
                        {
                            (0, None, field.text().ok_or_else(loss)?.to_owned())
                        }
                        PersonalFieldType::Boolean => (
                            2,
                            None,
                            field
                                .text()
                                .map_or_else(|| field.value.to_string(), str::to_owned),
                        ),
                        PersonalFieldType::Reference => (
                            3,
                            field
                                .value
                                .get("linkedId")
                                .and_then(serde_json::Value::as_u64),
                            field
                                .value
                                .get("value")
                                .and_then(serde_json::Value::as_str)
                                .or_else(|| field.text())
                                .unwrap_or_default()
                                .to_owned(),
                        ),
                        PersonalFieldType::Unknown(t) if t.starts_with("bitwarden-") => (
                            t[10..].parse::<u64>()?,
                            None,
                            field.text().ok_or_else(loss)?.to_owned(),
                        ),
                        _ => return Err(loss()),
                    };
                    old.custom_fields.push(LegacyField {
                        name: if legacy_section == LegacyFieldSection::Custom {
                            field.label.clone()
                        } else {
                            field.id.clone()
                        },
                        value,
                        section: legacy_section,
                        field_type: if legacy_section == LegacyFieldSection::Custom {
                            ty
                        } else {
                            0
                        },
                        linked_id,
                    });
                }
            }
        }
        Ok(old)
    }
}

fn section_id(kind: PersonalSecretKind) -> &'static str {
    match kind {
        PersonalSecretKind::Login | PersonalSecretKind::Generic => "account",
        PersonalSecretKind::Card => "card",
        PersonalSecretKind::Identity => "identity",
        _ => "details",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_items_and_redacts_debug_output() {
        let mut item = PersonalSecret::generic("Example".into(), "do-not-log".into());
        item.notes = Some("do-not-log".into());
        item.source = Some(serde_json::json!({"private":"do-not-log"}));
        assert!(!format!("{item:?}").contains("do-not-log"));
        assert!(!format!("{:?}", item.sections[0].fields[0]).contains("do-not-log"));
        item.sections[0].fields[0].value = "x".repeat(512 * 1024).into();
        assert!(item.encode().unwrap_err().to_string().contains("512 KiB"));
        assert!(PersonalSecret::decode("binary", &[255]).is_err());
    }

    #[test]
    fn card_templates_export_by_field_id_and_renamed_login_fields_are_not_lost() {
        let mut card = PersonalSecret::template(PersonalSecretKind::Card, "Card".into());
        card.sections[0].fields[1].value = "001234".into();
        let output = export_manager(TransferFormat::BitwardenJson, &[card]).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(json["items"][0]["card"]["number"], "001234");
        assert!(json["items"][0]["card"].get("Card number").is_none());
        let mut login = PersonalSecret::generic("Account".into(), "p".into());
        login.sections[0].fields[0].label = "Recovery password".into();
        assert!(export_manager(TransferFormat::OnePasswordCsv, &[login]).is_err());
    }

    #[test]
    fn migrates_v1_and_plaintext_without_changing_values() {
        let v1 = br#"{"format":"factorseal-personal-secret","version":1,"kind":"card","title":"Card","username":"u","password":"p","urls":["https://one","https://two"],"totp":"otp","notes":"line 1\nline 2","folder":"Home","tags":["a"],"favorite":true,"archived":true,"custom_fields":[{"name":"number","value":"0123","section":"card"},{"name":"code","value":"009","section":"card"},{"name":"recovery","value":"abc"}]}"#;
        let item = PersonalSecret::decode("ignored", v1).unwrap();
        assert_eq!(item.version, 2);
        assert_eq!(item.title, "Card");
        assert_eq!(item.sections[0].fields.len(), 5);
        assert_eq!(item.sections[1].fields[0].text(), Some("0123"));
        assert_eq!(
            item.sections[1].fields[0].field_type,
            PersonalFieldType::CardNumber
        );
        assert!(item.sections[1].fields[1].concealed);
        assert_eq!(item.sections[2].fields[0].text(), Some("abc"));
        assert_eq!(
            item,
            PersonalSecret::decode("ignored", &item.encode().unwrap()).unwrap()
        );
        assert_eq!(item.id, PersonalSecret::decode("ignored", v1).unwrap().id);
        let plain = PersonalSecret::decode("Legacy", b"a\nb\n").unwrap();
        assert_eq!(plain.sections[0].fields[0].text(), Some("a\nb\n"));
    }

    #[test]
    fn every_template_round_trips_with_unique_ids_and_sensitive_fields_masked() {
        let mut ids = HashSet::new();
        for kind in PersonalSecretKind::ALL {
            let item = PersonalSecret::template(kind, kind.label().into());
            assert!(ids.insert(item.id.clone()));
            assert!(!item.sections[0].fields.is_empty());
            assert_eq!(
                item,
                PersonalSecret::decode("", &item.encode().unwrap()).unwrap()
            );
            for field in &item.sections[0].fields {
                if field.field_type.concealed() {
                    assert!(field.concealed);
                }
            }
        }
    }

    #[test]
    fn preserves_duplicate_labels_structured_values_and_unknown_types() {
        let mut item = PersonalSecret::new(PersonalSecretKind::Passport, "Travel".into());
        item.sections.push(PersonalSection {
            id: "recovery".into(),
            label: "Recovery".into(),
            fields: vec![
                PersonalField::new("one", "Code", PersonalFieldType::Concealed, "001"),
                PersonalField::new(
                    "two",
                    "Code",
                    PersonalFieldType::Unknown("future-type".into()),
                    serde_json::json!({"nested":["secret", true, 123]}),
                ),
            ],
        });
        let decoded = PersonalSecret::decode("", &item.encode().unwrap()).unwrap();
        assert_eq!(decoded, item);
        assert_eq!(decoded.sections[0].fields[1].value["nested"][0], "secret");
        assert!(
            export_manager(TransferFormat::BitwardenJson, &[item])
                .unwrap_err()
                .to_string()
                .contains("lossless")
        );
    }

    #[test]
    fn rejects_future_versions_duplicate_ids_and_wrong_value_types() {
        let mut item = PersonalSecret::generic("Example".into(), "secret".into());
        let mut value: serde_json::Value = serde_json::from_slice(&item.encode().unwrap()).unwrap();
        value["version"] = 99.into();
        assert!(PersonalSecret::decode("", &serde_json::to_vec(&value).unwrap()).is_err());
        item.sections[0].fields.push(PersonalField::new(
            "password",
            "Another",
            PersonalFieldType::Text,
            "x",
        ));
        assert!(item.encode().is_err());
        item.sections[0].fields.pop();
        item.sections[0].fields[0].value = serde_json::json!({"unexpected":"secret"});
        assert!(item.encode().is_err());
        item.sections[0].fields[0].value = "x".into();
        item.sections[0].fields[0].concealed = false;
        assert!(item.encode().is_err());
    }

    #[test]
    fn bitwarden_preserves_field_types_links_and_unmapped_data() {
        let bytes = br#"{"items":[{"id":"stable","type":1,"name":"Login","login":{"password":"p"},"fields":[{"name":"PIN","value":"001","type":1},{"name":"Flag","value":"false","type":2},{"name":"Linked","value":null,"type":3,"linkedId":100},{"name":"Future","value":"raw","type":9}]}]}"#;
        let items = import_manager(TransferFormat::BitwardenJson, bytes).unwrap();
        assert_eq!(items[0].id, "bitwarden-stable");
        let fields = &items[0].sections[1].fields;
        assert_eq!(fields[0].field_type, PersonalFieldType::Concealed);
        assert_eq!(fields[1].field_type, PersonalFieldType::Boolean);
        assert_eq!(fields[2].value["linkedId"], 100);
        assert_eq!(
            fields[3].field_type,
            PersonalFieldType::Unknown("bitwarden-9".into())
        );
        let exported = export_manager(TransferFormat::BitwardenJson, &items).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&exported).unwrap();
        assert_eq!(json["items"][0]["fields"][0]["type"], 1);
        assert_eq!(json["items"][0]["fields"][2]["linkedId"], 100);
        assert_eq!(json["items"][0]["fields"][3]["type"], 9);
        let passkey = br#"{"items":[{"type":1,"name":"Passkey","login":{"fido2Credentials":[{"keyValue":"private-key"}]}}]}"#;
        let items = import_manager(TransferFormat::BitwardenJson, passkey).unwrap();
        assert!(
            items[0]
                .source
                .as_ref()
                .unwrap()
                .to_string()
                .contains("private-key")
        );
        assert!(export_manager(TransferFormat::BitwardenJson, &items).is_err());
        assert_eq!(
            items[0],
            PersonalSecret::decode("", &items[0].encode().unwrap()).unwrap()
        );
    }

    #[test]
    fn csv_unknown_columns_preserve_values_and_block_lossy_export() {
        let bytes = b"Title,Password,Recovery code,Security question\nExample,p,001,First pet?\n";
        let items = import_manager(TransferFormat::OnePasswordCsv, bytes).unwrap();
        assert_eq!(items[0].sections[1].fields[0].text(), Some("001"));
        assert!(items[0].sections[1].fields[0].concealed);
        assert_eq!(items[0].sections[1].fields[1].label, "Security question");
        assert!(export_manager(TransferFormat::OnePasswordCsv, &items).is_err());
        assert!(
            import_manager(
                TransferFormat::OnePasswordCsv,
                b"Title,Password,Password\nExample,p,q\n"
            )
            .is_err()
        );
        assert!(
            import_manager(
                TransferFormat::OnePasswordCsv,
                b"Title,Password\nExample,p,extra\n"
            )
            .is_err()
        );
    }

    #[test]
    fn real_fixtures_survive_native_storage() {
        for (format, bytes) in [
            (
                TransferFormat::BitwardenJson,
                include_bytes!("../../tests/fixtures/transfer/keepassxc/bitwarden_export.json")
                    .as_slice(),
            ),
            (
                TransferFormat::OnePasswordCsv,
                include_bytes!("../../tests/fixtures/transfer/onepassword8.csv").as_slice(),
            ),
            (
                TransferFormat::KeePassCsv,
                include_bytes!("../../tests/fixtures/transfer/keepass-official.csv").as_slice(),
            ),
        ] {
            for item in import_manager(format, bytes).unwrap() {
                assert_eq!(
                    item,
                    PersonalSecret::decode("", &item.encode().unwrap()).unwrap()
                );
            }
        }
    }
}

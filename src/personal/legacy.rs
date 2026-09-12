//! Compatibility with previously stored personal items.
use super::*;

const PERSONAL_VERSION: u16 = 1;

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacyField {
    pub(crate) name: String,
    pub(crate) value: String,
    #[serde(default, skip_serializing_if = "LegacyFieldSection::is_custom")]
    pub(crate) section: LegacyFieldSection,
    #[serde(default)]
    pub(crate) field_type: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) linked_id: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum LegacyFieldSection {
    #[default]
    Custom,
    Card,
    Identity,
}

impl LegacyFieldSection {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_custom(&self) -> bool {
        matches!(self, Self::Custom)
    }
}

impl Drop for LegacyField {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LegacySecret {
    format: String,
    version: u16,
    pub(crate) kind: PersonalSecretKind,
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
    pub(crate) custom_fields: Vec<LegacyField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) folder: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) tags: Vec<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) favorite: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub(crate) archived: bool,
}

impl LegacySecret {
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
            std::str::from_utf8(bytes)
                .context("legacy personal secret is not UTF-8")?
                .to_owned(),
        ))
    }

    fn is_supported(&self) -> bool {
        self.format == PERSONAL_FORMAT && self.version == PERSONAL_VERSION
    }

    #[cfg(feature = "transfer")]
    pub(crate) fn new(kind: PersonalSecretKind, title: String) -> Self {
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

impl Drop for LegacySecret {
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

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

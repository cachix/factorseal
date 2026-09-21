//! Portable Secret Service records, independent of the native D-Bus adapter.

use super::{SecretAddress, VaultError, VaultResult, WireSecret};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub(crate) const NAMESPACE: &[u8] = b"factorseal/secret-service/v1";
pub(crate) const INDEX_ITEM: &str = "secret-service-index";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Index {
    version: u8,
    pub(crate) items: Vec<IndexItem>,
}

impl Default for Index {
    fn default() -> Self {
        Self {
            version: 1,
            items: Vec::new(),
        }
    }
}

impl Index {
    pub(crate) fn decode(bytes: Option<&[u8]>) -> VaultResult<Self> {
        let index: Self = bytes
            .map_or_else(|| Ok(Self::default()), serde_json::from_slice)
            .map_err(|error| {
                VaultError::InvalidData(format!("invalid Secret Service index: {error}"))
            })?;
        let mut ids = HashSet::new();
        if index.version != 1 || index.items.len() > 100_000 {
            return Err(VaultError::InvalidData(
                "unsupported Secret Service index".to_owned(),
            ));
        }
        for item in &index.items {
            item.validate()?;
            if !ids.insert(&item.id) {
                return Err(VaultError::InvalidData(
                    "duplicate Secret Service item ID".to_owned(),
                ));
            }
        }
        Ok(index)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct IndexItem {
    pub(crate) id: String,
    pub(crate) label: String,
    pub(crate) attributes: HashMap<String, String>,
    pub(crate) content_type: String,
    pub(crate) created: u64,
    pub(crate) modified: u64,
}

impl IndexItem {
    fn validate(&self) -> VaultResult<()> {
        if self.id.len() != 32 || !self.id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(VaultError::InvalidData(
                "invalid Secret Service item ID".to_owned(),
            ));
        }
        Ok(())
    }
    pub(crate) fn address(&self) -> VaultResult<SecretAddress> {
        SecretAddress::new(format!("item/{}", self.id), None)
    }
}

/// Metadata and value travel together and are committed in one transaction.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PortableItem {
    version: u8,
    pub(crate) item: IndexItem,
    pub(crate) value: WireSecret,
}

impl PortableItem {
    pub(crate) fn new(item: IndexItem, value: WireSecret) -> Self {
        Self {
            version: 1,
            item,
            value,
        }
    }
    pub(crate) fn encode(&self) -> VaultResult<WireSecret> {
        let bytes = serde_json::to_vec(self).map_err(|e| VaultError::InvalidData(e.to_string()))?;
        WireSecret::new(bytes)
    }
    pub(crate) fn decode(bytes: &[u8], address: &SecretAddress) -> VaultResult<Self> {
        let item: Self =
            serde_json::from_slice(bytes).map_err(|e| VaultError::InvalidData(e.to_string()))?;
        item.item.validate()?;
        if item.version != 1 || item.item.address()? != *address {
            return Err(VaultError::InvalidData(
                "invalid portable Secret Service item".to_owned(),
            ));
        }
        Ok(item)
    }
}

#[cfg(any(
    feature = "vault-store",
    all(feature = "secret-service-host", target_os = "linux")
))]
pub(crate) fn service_target(attributes: &HashMap<String, String>) -> String {
    use sha2::{Digest as _, Sha256};
    if let Some(service) = attributes
        .get("service")
        .filter(|service| !service.is_empty())
    {
        return format!("service/{service}");
    }
    let ordered: std::collections::BTreeMap<_, _> = attributes.iter().collect();
    format!(
        "attributes/{}",
        hex::encode(Sha256::digest(
            serde_json::to_vec(&ordered).expect("string map serializes")
        ))
    )
}

/// Shared with approval creation so inventory never guesses from display labels.
#[cfg(feature = "vault-store")]
pub(crate) fn access_project(service: &str) -> (String, Option<String>) {
    let parts: Vec<_> = service
        .strip_prefix("service/")
        .unwrap_or(service)
        .splitn(4, '/')
        .collect();
    if parts.len() == 4 && parts[0] == "secretspec" && !parts[1].is_empty() && !parts[2].is_empty()
    {
        (
            format!("secretspec/{}", parts[1]),
            Some(parts[2].to_owned()),
        )
    } else {
        (service.to_owned(), None)
    }
}

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
        serde_json::to_vec(self)
            .map(WireSecret::new)
            .map_err(|e| VaultError::InvalidData(e.to_string()))
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

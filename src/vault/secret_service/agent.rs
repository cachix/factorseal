use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use zbus::fdo;
use zeroize::Zeroizing;

use super::{SessionState, failed, no_item, poisoned, random_id, secret_item, unix_time};
use crate::vault::{
    CallerIdentity, VaultAction, VaultError, VaultMutation, VaultRequest, VaultResponseBody,
    VaultResult, VaultService, WireSecret, WireSecretAddress,
};

pub(super) const NAMESPACE: &[u8] = b"factorseal/secret-service/v1";
pub(super) const INDEX_ITEM: &str = "secret-service-index";
const INDEX_VERSION: u8 = 1;

#[derive(Clone)]
pub(super) struct Store {
    pub(super) service: Arc<VaultService>,
    pub(super) caller: CallerIdentity,
}

impl Store {
    fn call(&self, action: VaultAction) -> VaultResult<VaultResponseBody> {
        let request = VaultRequest::new(action)?;
        self.service
            .handle(&self.caller, request, unix_time())
            .result
            .map_err(|error| VaultError::Protocol(error.message))
    }

    pub(super) fn get(&self, item: impl Into<String>) -> VaultResult<Option<Zeroizing<Vec<u8>>>> {
        let response = self.call(VaultAction::Get {
            namespace: NAMESPACE.to_vec(),
            address: WireSecretAddress::new(item, None),
        })?;
        match response {
            VaultResponseBody::Secret { value } => {
                Ok(value.map(|value| Zeroizing::new(value.expose().to_vec())))
            }
            _ => Err(VaultError::Protocol(
                "unexpected Secret Service vault response".to_owned(),
            )),
        }
    }

    fn mutate(&self, mutations: Vec<VaultMutation>) -> VaultResult<()> {
        match self.call(VaultAction::Mutate {
            namespace: NAMESPACE.to_vec(),
            mutations,
        })? {
            VaultResponseBody::Mutated => Ok(()),
            _ => Err(VaultError::Protocol(
                "unexpected Secret Service vault response".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub(super) struct Index {
    version: u8,
    pub(super) items: Vec<IndexItem>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct IndexItem {
    pub(super) id: String,
    pub(super) label: String,
    pub(super) attributes: HashMap<String, String>,
    pub(super) content_type: String,
    pub(super) created: u64,
    pub(super) modified: u64,
}

pub(super) struct Agent {
    pub(super) store: Store,
    index: Mutex<Index>,
    pub(super) sessions: Mutex<HashMap<String, SessionState>>,
}

impl Agent {
    pub(super) fn load(store: Store) -> VaultResult<Self> {
        let index = match store.get(INDEX_ITEM)? {
            Some(bytes) => serde_json::from_slice::<Index>(&bytes).map_err(|error| {
                VaultError::InvalidData(format!("invalid Secret Service index: {error}"))
            })?,
            None => Index {
                version: INDEX_VERSION,
                items: Vec::new(),
            },
        };
        if index.version != INDEX_VERSION {
            return Err(VaultError::InvalidData(
                "unsupported Secret Service index version".to_owned(),
            ));
        }
        Ok(Self {
            store,
            index: Mutex::new(index),
            sessions: Mutex::new(HashMap::new()),
        })
    }

    pub(super) fn item_ids(&self) -> VaultResult<Vec<String>> {
        Ok(self
            .index
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?
            .items
            .iter()
            .map(|item| item.id.clone())
            .collect())
    }

    pub(super) fn item(&self, id: &str) -> fdo::Result<IndexItem> {
        self.index
            .lock()
            .map_err(poisoned)?
            .items
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or_else(|| no_item(id))
    }

    pub(super) fn all_items(&self) -> fdo::Result<Vec<IndexItem>> {
        Ok(self.index.lock().map_err(poisoned)?.items.clone())
    }

    pub(super) fn create_or_replace(
        &self,
        label: String,
        attributes: HashMap<String, String>,
        value: &Zeroizing<Vec<u8>>,
        content_type: String,
        replace: bool,
    ) -> fdo::Result<(IndexItem, bool)> {
        let mut index = self.index.lock().map_err(poisoned)?;
        let existing = index
            .items
            .iter()
            .position(|item| item.attributes == attributes);
        let id = match (existing, replace) {
            (Some(position), true) => index.items[position].id.clone(),
            (Some(_), false) => {
                return Err(fdo::Error::Failed(
                    "an item with these attributes already exists".to_owned(),
                ));
            }
            (None, _) => random_id().map_err(failed)?,
        };
        let now = unix_time();
        let item = IndexItem {
            id: id.clone(),
            label,
            attributes,
            content_type,
            created: existing.map_or(now, |position| index.items[position].created),
            modified: now,
        };
        let created = existing.is_none();
        let mut next = index.clone();
        if let Some(position) = existing {
            next.items[position] = item.clone();
        } else {
            next.items.push(item.clone());
        }
        let index_bytes = serde_json::to_vec(&next).map_err(failed)?;
        self.store
            .mutate(vec![
                VaultMutation::Put {
                    address: WireSecretAddress::new(secret_item(&id), None),
                    value: WireSecret::new(value.to_vec()),
                    evict_at: None,
                },
                VaultMutation::Put {
                    address: WireSecretAddress::new(INDEX_ITEM, None),
                    value: WireSecret::new(index_bytes),
                    evict_at: None,
                },
            ])
            .map_err(failed)?;
        *index = next;
        Ok((item, created))
    }

    pub(super) fn set_secret(
        &self,
        id: &str,
        value: &Zeroizing<Vec<u8>>,
        content_type: String,
    ) -> fdo::Result<()> {
        let mut index = self.index.lock().map_err(poisoned)?;
        let mut next = index.clone();
        let item = next
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| no_item(id))?;
        item.content_type = content_type;
        item.modified = unix_time();
        let index_bytes = serde_json::to_vec(&next).map_err(failed)?;
        self.store
            .mutate(vec![
                VaultMutation::Put {
                    address: WireSecretAddress::new(secret_item(id), None),
                    value: WireSecret::new(value.to_vec()),
                    evict_at: None,
                },
                VaultMutation::Put {
                    address: WireSecretAddress::new(INDEX_ITEM, None),
                    value: WireSecret::new(index_bytes),
                    evict_at: None,
                },
            ])
            .map_err(failed)?;
        *index = next;
        Ok(())
    }

    pub(super) fn delete_item(&self, id: &str) -> fdo::Result<()> {
        let mut index = self.index.lock().map_err(poisoned)?;
        let mut next = index.clone();
        let Some(position) = next.items.iter().position(|item| item.id == id) else {
            return Err(no_item(id));
        };
        next.items.remove(position);
        let index_bytes = serde_json::to_vec(&next).map_err(failed)?;
        self.store
            .mutate(vec![
                VaultMutation::Delete {
                    address: WireSecretAddress::new(secret_item(id), None),
                },
                VaultMutation::Put {
                    address: WireSecretAddress::new(INDEX_ITEM, None),
                    value: WireSecret::new(index_bytes),
                    evict_at: None,
                },
            ])
            .map_err(failed)?;
        *index = next;
        Ok(())
    }
}

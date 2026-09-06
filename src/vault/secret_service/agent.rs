//! Item index and vault access for the Secret Service adapter.

use std::collections::HashMap;
use std::sync::Arc;

use sha2::{Digest as _, Sha256};
use zbus::fdo;
use zeroize::Zeroizing;

use super::{failed, no_item, random_id, secret_item, unix_time};
use crate::vault::{
    VaultAction, VaultClient, VaultError, VaultMutation, VaultRequest, VaultResponse,
    VaultResponseBody, VaultResult, WireSecret, WireSecretAddress,
};

pub(super) use crate::vault::secret_service_data::{INDEX_ITEM, Index, IndexItem};
/// Vault namespace holding Secret Service items and their index.
pub const NAMESPACE: &[u8] = crate::vault::secret_service_data::NAMESPACE;

/// Where the adapter's vault requests go: the in-process service of the
/// headless agent, or the native socket of the Desktop's vault worker.
trait Backend: Send + Sync {
    fn request(&self, request: VaultRequest) -> VaultResult<VaultResponse>;
}

#[cfg(feature = "vault")]
struct InProcess {
    service: std::sync::Arc<crate::vault::VaultService>,
    caller: crate::vault::CallerIdentity,
}

#[cfg(feature = "vault")]
impl Backend for InProcess {
    fn request(&self, request: VaultRequest) -> VaultResult<VaultResponse> {
        Ok(self.service.handle(&self.caller, request, unix_time()))
    }
}

struct Remote {
    client: Box<dyn VaultClient>,
}

impl Backend for Remote {
    fn request(&self, request: VaultRequest) -> VaultResult<VaultResponse> {
        self.client.request(&request)
    }
}

#[derive(Clone)]
pub(super) struct Store {
    backend: Arc<dyn Backend>,
}

impl Store {
    #[cfg(test)]
    pub(super) fn backend_request(&self, request: VaultRequest) -> VaultResult<VaultResponse> {
        self.backend.request(request)
    }

    fn index(&self) -> VaultResult<Index> {
        let bytes = self.get(INDEX_ITEM)?;
        Index::decode(bytes.as_deref())
    }

    #[cfg(feature = "vault")]
    pub(super) fn in_process(
        service: std::sync::Arc<crate::vault::VaultService>,
        caller: crate::vault::CallerIdentity,
    ) -> Self {
        Self {
            backend: Arc::new(InProcess { service, caller }),
        }
    }

    pub(super) fn remote(client: Box<dyn VaultClient>) -> Self {
        Self {
            backend: Arc::new(Remote { client }),
        }
    }

    fn call(&self, action: VaultAction) -> VaultResult<VaultResponseBody> {
        let request = VaultRequest::new(action)?;
        let response = self.backend.request(request)?;
        response.check_delivery()?;
        response.result.map_err(|error| {
            if error.code == crate::vault::VaultResponseErrorCode::Conflict {
                VaultError::Conflict
            } else {
                VaultError::Protocol(error.message)
            }
        })
    }

    pub(super) fn get(
        &self,
        item: impl Into<String>,
    ) -> VaultResult<Option<crate::security::LockedBytes>> {
        let response = self.call(VaultAction::Get {
            namespace: NAMESPACE.to_vec(),
            address: WireSecretAddress::new(item, None),
        })?;
        match response {
            VaultResponseBody::Secret { value } => Ok(value.map(WireSecret::into_locked)),
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

    /// `Lock` seals the whole vault through the adapter's own grant.
    pub(super) fn seal(&self) -> VaultResult<()> {
        match self.call(VaultAction::Seal {
            namespace: NAMESPACE.to_vec(),
        })? {
            VaultResponseBody::Sealed => Ok(()),
            _ => Err(VaultError::Protocol(
                "unexpected Secret Service vault response".to_owned(),
            )),
        }
    }
}

pub(super) struct Agent {
    pub(super) store: Store,
}

impl Agent {
    pub(super) fn load(store: Store) -> VaultResult<Self> {
        store.index()?;
        Ok(Self { store })
    }

    pub(super) fn item_ids(&self) -> VaultResult<Vec<String>> {
        self.all_items()
            .map(|items| items.into_iter().map(|item| item.id).collect())
            .map_err(|error| VaultError::Protocol(error.to_string()))
    }

    pub(super) fn item(&self, id: &str) -> fdo::Result<IndexItem> {
        self.all_items()?
            .into_iter()
            .find(|item| item.id == id)
            .ok_or_else(|| no_item(id))
    }

    pub(super) fn all_items(&self) -> fdo::Result<Vec<IndexItem>> {
        Ok(self.store.index().map_err(failed)?.items)
    }

    // Keep the owned D-Bus inputs available when a concurrent writer requires a retry.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn create_or_replace(
        &self,
        label: String,
        attributes: HashMap<String, String>,
        value: &Zeroizing<Vec<u8>>,
        content_type: String,
        replace: bool,
    ) -> fdo::Result<(IndexItem, bool)> {
        for _ in 0..16 {
            let expected = self.store.get(INDEX_ITEM).map_err(failed)?;
            let index = Index::decode(expected.as_deref()).map_err(failed)?;
            let existing = replace
                .then(|| {
                    index
                        .items
                        .iter()
                        .position(|item| item.attributes == attributes)
                })
                .flatten();
            let id = match existing {
                Some(position) => index.items[position].id.clone(),
                None => random_id().map_err(failed)?,
            };
            let now = unix_time();
            let item = IndexItem {
                id: id.clone(),
                label: label.clone(),
                attributes: attributes.clone(),
                content_type: content_type.clone(),
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
            let result = self.store.mutate(vec![
                VaultMutation::Check {
                    address: WireSecretAddress::new(INDEX_ITEM, None),
                    expected_sha256: expected
                        .as_ref()
                        .map(|bytes| Sha256::digest(bytes.as_slice()).into()),
                },
                VaultMutation::Put {
                    address: WireSecretAddress::new(secret_item(&id), None),
                    value: WireSecret::new(value.to_vec()).map_err(failed)?,
                    evict_at: None,
                },
                VaultMutation::Put {
                    address: WireSecretAddress::new(INDEX_ITEM, None),
                    value: WireSecret::new(index_bytes).map_err(failed)?,
                    evict_at: None,
                },
            ]);
            if matches!(result, Err(VaultError::Conflict)) {
                continue;
            }
            result.map_err(failed)?;
            return Ok((item, created));
        }
        Err(failed(
            "Secret Service index changed repeatedly; retry the operation",
        ))
    }

    // Keep the owned D-Bus inputs available when a concurrent writer requires a retry.
    #[allow(clippy::needless_pass_by_value)]
    pub(super) fn set_secret(
        &self,
        id: &str,
        value: &Zeroizing<Vec<u8>>,
        content_type: String,
    ) -> fdo::Result<()> {
        for _ in 0..16 {
            let expected = self.store.get(INDEX_ITEM).map_err(failed)?;
            let index = Index::decode(expected.as_deref()).map_err(failed)?;
            let mut next = index.clone();
            let item = next
                .items
                .iter_mut()
                .find(|item| item.id == id)
                .ok_or_else(|| no_item(id))?;
            item.content_type.clone_from(&content_type);
            item.modified = unix_time();
            let index_bytes = serde_json::to_vec(&next).map_err(failed)?;
            let result = self.store.mutate(vec![
                VaultMutation::Check {
                    address: WireSecretAddress::new(INDEX_ITEM, None),
                    expected_sha256: expected
                        .as_ref()
                        .map(|bytes| Sha256::digest(bytes.as_slice()).into()),
                },
                VaultMutation::Put {
                    address: WireSecretAddress::new(secret_item(id), None),
                    value: WireSecret::new(value.to_vec()).map_err(failed)?,
                    evict_at: None,
                },
                VaultMutation::Put {
                    address: WireSecretAddress::new(INDEX_ITEM, None),
                    value: WireSecret::new(index_bytes).map_err(failed)?,
                    evict_at: None,
                },
            ]);
            if matches!(result, Err(VaultError::Conflict)) {
                continue;
            }
            result.map_err(failed)?;
            return Ok(());
        }
        Err(failed(
            "Secret Service index changed repeatedly; retry the operation",
        ))
    }

    pub(super) fn delete_item(&self, id: &str) -> fdo::Result<()> {
        for _ in 0..16 {
            let expected = self.store.get(INDEX_ITEM).map_err(failed)?;
            let index = Index::decode(expected.as_deref()).map_err(failed)?;
            let mut next = index.clone();
            let Some(position) = next.items.iter().position(|item| item.id == id) else {
                return Err(no_item(id));
            };
            next.items.remove(position);
            let index_bytes = serde_json::to_vec(&next).map_err(failed)?;
            let result = self.store.mutate(vec![
                VaultMutation::Check {
                    address: WireSecretAddress::new(INDEX_ITEM, None),
                    expected_sha256: expected
                        .as_ref()
                        .map(|bytes| Sha256::digest(bytes.as_slice()).into()),
                },
                VaultMutation::Delete {
                    address: WireSecretAddress::new(secret_item(id), None),
                },
                VaultMutation::Put {
                    address: WireSecretAddress::new(INDEX_ITEM, None),
                    value: WireSecret::new(index_bytes).map_err(failed)?,
                    evict_at: None,
                },
            ]);
            if matches!(result, Err(VaultError::Conflict)) {
                continue;
            }
            result.map_err(failed)?;
            return Ok(());
        }
        Err(failed(
            "Secret Service index changed repeatedly; retry the operation",
        ))
    }
}

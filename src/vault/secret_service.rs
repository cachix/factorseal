//! Linux `org.freedesktop.secrets` adapter backed by the live Factorseal vault.
//!
//! The adapter is deliberately part of the unsealed vault process: it has no
//! database access of its own and disappears as soon as the vault seals.  The
//! session bus already authenticates peers as the current desktop user, which
//! is the same boundary provided by the other Secret Service implementations.

use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zbus::object_server::ObjectServer;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{Connection, fdo, interface};

use super::linux::linux_caller_identity_for_executable;
use super::{
    GrantPermission, VaultAction, VaultError, VaultRequest, VaultResponseBody, VaultResult,
    VaultService, WireSecret, WireSecretAddress,
};

const BUS_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/factorseal";
const DEFAULT_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";
const ITEM_PREFIX: &str = "/org/freedesktop/secrets/collection/factorseal/";
const SESSION_PREFIX: &str = "/org/freedesktop/secrets/session/";
const NAMESPACE: &[u8] = b"factorseal/secret-service/v1";
const INDEX_ITEM: &str = "secret-service-index";
const INDEX_VERSION: u8 = 1;

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
type Properties = HashMap<String, OwnedValue>;

/// Serve Secret Service until `stopping` is set or the vault seals.
///
/// The internal Factorseal binary is granted this namespace and mediates the
/// session-bus API. This is intentionally separate from grants issued to IPC
/// clients: a session-bus client never receives the vault socket capability.
pub(crate) fn serve_secret_service(
    service: Arc<VaultService>,
    stopping: Arc<AtomicBool>,
) -> VaultResult<()> {
    let executable = std::env::current_exe().map_err(|error| {
        VaultError::Protocol(format!("could not resolve Factorseal executable: {error}"))
    })?;
    let caller = linux_caller_identity_for_executable(executable)?;
    service.authorize_namespace(
        &caller,
        NAMESPACE,
        [
            GrantPermission::Get,
            GrantPermission::Put,
            GrantPermission::Delete,
            GrantPermission::Seal,
        ],
        None,
        unix_time(),
    )?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            VaultError::Protocol(format!("could not start Secret Service runtime: {error}"))
        })?;
    runtime.block_on(async move {
        let store = Store {
            service: Arc::clone(&service),
            caller,
        };
        let agent = Arc::new(Agent::load(store)?);
        let connection = Connection::session().await.map_err(dbus_error)?;
        connection
            .request_name_with_flags(BUS_NAME, zbus::fdo::RequestNameFlags::DoNotQueue.into())
            .await
            .map_err(dbus_error)?;
        let server = connection.object_server();
        server
            .at(
                SERVICE_PATH,
                Service {
                    agent: Arc::clone(&agent),
                },
            )
            .await
            .map_err(dbus_error)?;
        server
            .at(
                COLLECTION_PATH,
                Collection {
                    agent: Arc::clone(&agent),
                },
            )
            .await
            .map_err(dbus_error)?;
        server
            .at(
                DEFAULT_ALIAS_PATH,
                Collection {
                    agent: Arc::clone(&agent),
                },
            )
            .await
            .map_err(dbus_error)?;
        for id in agent.item_ids()? {
            let path = item_path(&id).map_err(|error| VaultError::Protocol(error.to_string()))?;
            server
                .at(
                    path,
                    Item {
                        agent: Arc::clone(&agent),
                        id,
                    },
                )
                .await
                .map_err(dbus_error)?;
        }

        while !stopping.load(Ordering::Acquire) && !service.expire_if_needed(unix_time())? {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Ok(())
    })
}

#[derive(Clone)]
struct Store {
    service: Arc<VaultService>,
    caller: super::CallerIdentity,
}

impl Store {
    fn call(&self, action: VaultAction) -> VaultResult<VaultResponseBody> {
        let request = VaultRequest::new(action)?;
        self.service
            .handle(&self.caller, request, unix_time())
            .result
            .map_err(|error| VaultError::Protocol(error.message))
    }

    fn get(&self, item: impl Into<String>) -> VaultResult<Option<Vec<u8>>> {
        let response = self.call(VaultAction::Get {
            namespace: NAMESPACE.to_vec(),
            address: WireSecretAddress::new(item, None),
        })?;
        match response {
            VaultResponseBody::Secret { value } => Ok(value.map(|value| value.expose().to_vec())),
            _ => Err(VaultError::Protocol(
                "unexpected Secret Service vault response".to_owned(),
            )),
        }
    }

    fn put(&self, item: impl Into<String>, value: Vec<u8>) -> VaultResult<()> {
        match self.call(VaultAction::Put {
            namespace: NAMESPACE.to_vec(),
            address: WireSecretAddress::new(item, None),
            value: WireSecret::new(value),
            evict_at: None,
        })? {
            VaultResponseBody::Stored => Ok(()),
            _ => Err(VaultError::Protocol(
                "unexpected Secret Service vault response".to_owned(),
            )),
        }
    }

    fn delete(&self, item: impl Into<String>) -> VaultResult<()> {
        match self.call(VaultAction::Delete {
            namespace: NAMESPACE.to_vec(),
            address: WireSecretAddress::new(item, None),
        })? {
            VaultResponseBody::Deleted { .. } => Ok(()),
            _ => Err(VaultError::Protocol(
                "unexpected Secret Service vault response".to_owned(),
            )),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct Index {
    version: u8,
    items: Vec<IndexItem>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct IndexItem {
    id: String,
    label: String,
    attributes: HashMap<String, String>,
    content_type: String,
    created: u64,
    modified: u64,
}

struct Agent {
    store: Store,
    index: Mutex<Index>,
    sessions: Mutex<HashMap<String, String>>,
}

impl Agent {
    fn load(store: Store) -> VaultResult<Self> {
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

    fn item_ids(&self) -> VaultResult<Vec<String>> {
        Ok(self
            .index
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)?
            .items
            .iter()
            .map(|item| item.id.clone())
            .collect())
    }

    fn item(&self, id: &str) -> fdo::Result<IndexItem> {
        self.index
            .lock()
            .map_err(poisoned)?
            .items
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or_else(|| no_item(id))
    }

    fn all_items(&self) -> fdo::Result<Vec<IndexItem>> {
        Ok(self.index.lock().map_err(poisoned)?.items.clone())
    }

    fn save_index(&self, index: &Index) -> fdo::Result<()> {
        self.store
            .put(INDEX_ITEM, serde_json::to_vec(index).map_err(failed)?)
            .map_err(failed)
    }

    fn create_or_replace(
        &self,
        label: String,
        attributes: HashMap<String, String>,
        value: Vec<u8>,
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
        self.store.put(secret_item(&id), value).map_err(failed)?;
        let created = existing.is_none();
        if let Some(position) = existing {
            index.items[position] = item.clone();
        } else {
            index.items.push(item.clone());
        }
        self.save_index(&index)?;
        Ok((item, created))
    }

    fn set_secret(&self, id: &str, value: Vec<u8>, content_type: String) -> fdo::Result<()> {
        self.store.put(secret_item(id), value).map_err(failed)?;
        let mut index = self.index.lock().map_err(poisoned)?;
        let item = index
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| no_item(id))?;
        item.content_type = content_type;
        item.modified = unix_time();
        self.save_index(&index)
    }

    fn delete_item(&self, id: &str) -> fdo::Result<()> {
        self.store.delete(secret_item(id)).map_err(failed)?;
        let mut index = self.index.lock().map_err(poisoned)?;
        let Some(position) = index.items.iter().position(|item| item.id == id) else {
            return Err(no_item(id));
        };
        index.items.remove(position);
        self.save_index(&index)
    }

    fn open_session(&self, path: String, owner: String) -> fdo::Result<()> {
        self.sessions.lock().map_err(poisoned)?.insert(path, owner);
        Ok(())
    }

    fn check_session(&self, path: &OwnedObjectPath, owner: &str) -> fdo::Result<()> {
        match self.sessions.lock().map_err(poisoned)?.get(path.as_str()) {
            Some(expected) if expected == owner => Ok(()),
            _ => Err(fdo::Error::Failed(
                "invalid Secret Service session".to_owned(),
            )),
        }
    }
}

struct Service {
    agent: Arc<Agent>,
}
struct Collection {
    agent: Arc<Agent>,
}
struct Item {
    agent: Arc<Agent>,
    id: String,
}
struct Session {
    agent: Arc<Agent>,
    owner: String,
    path: String,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    #[zbus(out_args("output", "result"))]
    async fn open_session(
        &self,
        algorithm: String,
        _input: OwnedValue,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        if algorithm != "plain" {
            return Err(fdo::Error::Failed(
                "Factorseal currently supports the plain Secret Service session algorithm"
                    .to_owned(),
            ));
        }
        let owner = sender(&header)?;
        let path = format!("{SESSION_PREFIX}{}", random_id().map_err(failed)?);
        self.agent.open_session(path.clone(), owner.clone())?;
        let object_path = object_path(&path)?;
        server
            .at(
                path.clone(),
                Session {
                    agent: Arc::clone(&self.agent),
                    owner,
                    path,
                },
            )
            .await
            .map_err(failed)?;
        let output =
            OwnedValue::try_from(zbus::zvariant::Value::from(String::new())).map_err(failed)?;
        Ok((output, object_path))
    }

    #[zbus(out_args("unlocked", "locked"))]
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        let paths = self
            .agent
            .all_items()?
            .into_iter()
            .filter(|item| {
                attributes
                    .iter()
                    .all(|(key, value)| item.attributes.get(key) == Some(value))
            })
            .map(|item| item_path(&item.id))
            .collect::<fdo::Result<Vec<_>>>()?;
        Ok((paths, Vec::new()))
    }

    #[zbus(out_args("unlocked", "prompt"))]
    fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        Ok((objects, root_path()?))
    }

    #[zbus(out_args("locked", "prompt"))]
    fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        self.agent.store.service.seal().map_err(failed)?;
        Ok((objects, root_path()?))
    }

    #[zbus(out_args("secrets",))]
    fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<HashMap<OwnedObjectPath, Secret>> {
        self.agent.check_session(&session, &sender(&header)?)?;
        let mut result = HashMap::new();
        for path in items {
            let id = item_id(path.as_str())?;
            let item = self.agent.item(id)?;
            let value = self
                .agent
                .store
                .get(secret_item(id))
                .map_err(failed)?
                .ok_or_else(|| no_item(id))?;
            result.insert(
                path,
                (session.clone(), Vec::new(), value, item.content_type),
            );
        }
        Ok(result)
    }

    #[zbus(out_args("collection",))]
    fn read_alias(&self, name: String) -> fdo::Result<OwnedObjectPath> {
        if name == "default" {
            object_path(DEFAULT_ALIAS_PATH)
        } else {
            root_path()
        }
    }

    #[zbus(property)]
    fn collections(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
        Ok(vec![object_path(COLLECTION_PATH)?])
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(out_args("results",))]
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<Vec<OwnedObjectPath>> {
        self.agent
            .all_items()?
            .into_iter()
            .filter(|item| {
                attributes
                    .iter()
                    .all(|(key, value)| item.attributes.get(key) == Some(value))
            })
            .map(|item| item_path(&item.id))
            .collect()
    }

    #[zbus(out_args("item", "prompt"))]
    async fn create_item(
        &self,
        properties: Properties,
        secret: Secret,
        replace: bool,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        self.agent.check_session(&secret.0, &sender(&header)?)?;
        if !secret.1.is_empty() {
            return Err(fdo::Error::Failed(
                "plain sessions do not use parameters".to_owned(),
            ));
        }
        let label = property_string(&properties, "org.freedesktop.Secret.Item.Label")?;
        let attributes = property_map(&properties, "org.freedesktop.Secret.Item.Attributes")?;
        let (item, created) = self
            .agent
            .create_or_replace(label, attributes, secret.2, secret.3, replace)?;
        let path = item_path(&item.id)?;
        if created {
            server
                .at(
                    path.clone(),
                    Item {
                        agent: Arc::clone(&self.agent),
                        id: item.id,
                    },
                )
                .await
                .map_err(failed)?;
        }
        Ok((path, root_path()?))
    }

    #[zbus(property)]
    fn items(&self) -> fdo::Result<Vec<OwnedObjectPath>> {
        self.agent
            .all_items()?
            .into_iter()
            .map(|item| item_path(&item.id))
            .collect()
    }
    #[zbus(property)]
    fn label(&self) -> String {
        "Factorseal".to_owned()
    }
    #[zbus(property)]
    fn locked(&self) -> bool {
        false
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("secret",))]
    fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<Secret> {
        self.agent.check_session(&session, &sender(&header)?)?;
        let item = self.agent.item(&self.id)?;
        let value = self
            .agent
            .store
            .get(secret_item(&self.id))
            .map_err(failed)?
            .ok_or_else(|| no_item(&self.id))?;
        Ok((session, Vec::new(), value, item.content_type))
    }

    fn set_secret(
        &self,
        secret: Secret,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<()> {
        self.agent.check_session(&secret.0, &sender(&header)?)?;
        if !secret.1.is_empty() {
            return Err(fdo::Error::Failed(
                "plain sessions do not use parameters".to_owned(),
            ));
        }
        self.agent.set_secret(&self.id, secret.2, secret.3)
    }

    #[zbus(out_args("prompt",))]
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<OwnedObjectPath> {
        self.agent.delete_item(&self.id)?;
        server
            .remove::<Item, _>(item_path(&self.id)?)
            .await
            .map_err(failed)?;
        root_path()
    }

    #[zbus(property)]
    fn label(&self) -> fdo::Result<String> {
        Ok(self.agent.item(&self.id)?.label)
    }
    #[zbus(property)]
    fn attributes(&self) -> fdo::Result<HashMap<String, String>> {
        Ok(self.agent.item(&self.id)?.attributes)
    }
    #[zbus(property)]
    fn locked(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn created(&self) -> fdo::Result<u64> {
        Ok(self.agent.item(&self.id)?.created)
    }
    #[zbus(property)]
    fn modified(&self) -> fdo::Result<u64> {
        Ok(self.agent.item(&self.id)?.modified)
    }
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    fn close(&self, #[zbus(header)] header: zbus::message::Header<'_>) -> fdo::Result<()> {
        if sender(&header)? != self.owner {
            return Err(fdo::Error::Failed(
                "Secret Service session belongs to another client".to_owned(),
            ));
        }
        self.agent
            .sessions
            .lock()
            .map_err(poisoned)?
            .remove(&self.path);
        Ok(())
    }
}

fn sender(header: &zbus::message::Header<'_>) -> fdo::Result<String> {
    header
        .sender()
        .map(ToString::to_string)
        .ok_or_else(|| fdo::Error::Failed("D-Bus caller has no unique name".to_owned()))
}
fn object_path(value: &str) -> fdo::Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(value).map_err(failed)
}
fn root_path() -> fdo::Result<OwnedObjectPath> {
    object_path("/")
}
fn item_path(id: &str) -> fdo::Result<OwnedObjectPath> {
    object_path(&format!("{ITEM_PREFIX}{id}"))
}
fn item_id(path: &str) -> fdo::Result<&str> {
    path.strip_prefix(ITEM_PREFIX)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| fdo::Error::Failed("unknown Secret Service item".to_owned()))
}
fn secret_item(id: &str) -> String {
    format!("item/{id}")
}
fn random_id() -> VaultResult<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}
fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn dbus_error(error: zbus::Error) -> VaultError {
    VaultError::Protocol(format!("Secret Service D-Bus error: {error}"))
}
fn failed(error: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(error.to_string())
}
fn poisoned<T>(_: std::sync::PoisonError<T>) -> fdo::Error {
    fdo::Error::Failed("Secret Service state lock was poisoned".to_owned())
}
fn no_item(id: &str) -> fdo::Error {
    fdo::Error::Failed(format!("no Secret Service item {id}"))
}
fn property_string(properties: &Properties, key: &str) -> fdo::Result<String> {
    let value = properties
        .get(key)
        .ok_or_else(|| fdo::Error::Failed(format!("missing {key}")))?;
    String::try_from(value.try_clone().map_err(failed)?)
        .map_err(|_| fdo::Error::Failed(format!("invalid {key}")))
}

fn property_map(properties: &Properties, key: &str) -> fdo::Result<HashMap<String, String>> {
    let value = properties
        .get(key)
        .ok_or_else(|| fdo::Error::Failed(format!("missing {key}")))?;
    HashMap::<String, String>::try_from(value.try_clone().map_err(failed)?)
        .map_err(|_| fdo::Error::Failed(format!("invalid {key}")))
}

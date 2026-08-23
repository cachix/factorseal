//! Linux `org.freedesktop.secrets` adapter backed by the live Factorseal vault.
//!
//! The adapter is deliberately part of the unsealed vault process: it has no
//! database access of its own and disappears as soon as the vault seals.  The
//! session bus already authenticates peers as the current desktop user, which
//! is the same boundary provided by the other Secret Service implementations.

#![allow(clippy::needless_pass_by_value, clippy::unused_self)]
// zbus interface methods must own decoded D-Bus arguments, including headers
// and object paths; changing these signatures to references breaks dispatch.

use std::collections::HashMap;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secret_service_protocol::{Session as ProtocolSession, SessionOutput};
use serde::{Deserialize, Serialize};
use zbus::object_server::ObjectServer;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{Connection, fdo, interface};

use super::linux::linux_caller_identity_for_executable;
use super::{
    GrantPermission, VaultAction, VaultError, VaultMutation, VaultRequest, VaultResponseBody,
    VaultResult, VaultService, WireSecret, WireSecretAddress,
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
struct Index {
    version: u8,
    items: Vec<IndexItem>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
    sessions: Mutex<HashMap<String, SessionState>>,
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
                    value: WireSecret::new(value),
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

    fn set_secret(&self, id: &str, value: Vec<u8>, content_type: String) -> fdo::Result<()> {
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
                    value: WireSecret::new(value),
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

    fn delete_item(&self, id: &str) -> fdo::Result<()> {
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

    fn open_session(
        &self,
        path: String,
        owner: String,
        session: ProtocolSession,
    ) -> fdo::Result<()> {
        self.sessions
            .lock()
            .map_err(poisoned)?
            .insert(path, SessionState { owner, session });
        Ok(())
    }

    fn session(&self, path: &OwnedObjectPath, owner: &str) -> fdo::Result<ProtocolSession> {
        match self.sessions.lock().map_err(poisoned)?.get(path.as_str()) {
            Some(session) if session.owner == owner => Ok(session.session.clone()),
            _ => Err(fdo::Error::Failed(
                "invalid Secret Service session".to_owned(),
            )),
        }
    }

    fn decrypt_secret(&self, secret: Secret, owner: &str) -> fdo::Result<(Vec<u8>, String)> {
        let value = self
            .session(&secret.0, owner)?
            .decrypt(&secret.1, &secret.2)
            .map_err(failed)?;
        Ok((value.to_vec(), secret.3))
    }

    fn encrypt_secret(
        &self,
        session: OwnedObjectPath,
        owner: &str,
        value: Vec<u8>,
        content_type: String,
    ) -> fdo::Result<Secret> {
        let value = self
            .session(&session, owner)?
            .encrypt(&value)
            .map_err(failed)?;
        Ok((
            session,
            value.parameters,
            value.value.to_vec(),
            content_type,
        ))
    }
}

#[derive(Clone)]
struct SessionState {
    owner: String,
    session: ProtocolSession,
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
        input: OwnedValue,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(OwnedValue, OwnedObjectPath)> {
        let input = session_input(&algorithm, input)?;
        let (session, output) = ProtocolSession::open(&algorithm, &input).map_err(failed)?;
        let owner = sender(&header)?;
        let path = format!("{SESSION_PREFIX}{}", random_id().map_err(failed)?);
        self.agent
            .open_session(path.clone(), owner.clone(), session)?;
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
        Ok((session_output(output)?, object_path))
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
        let owner = sender(&header)?;
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
                self.agent
                    .encrypt_secret(session.clone(), &owner, value, item.content_type)?,
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
        let (value, content_type) = self.agent.decrypt_secret(secret, &sender(&header)?)?;
        let label = property_string(&properties, "org.freedesktop.Secret.Item.Label")?;
        let attributes = property_map(&properties, "org.freedesktop.Secret.Item.Attributes")?;
        let (item, created) =
            self.agent
                .create_or_replace(label, attributes, value, content_type, replace)?;
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
        let owner = sender(&header)?;
        let item = self.agent.item(&self.id)?;
        let value = self
            .agent
            .store
            .get(secret_item(&self.id))
            .map_err(failed)?
            .ok_or_else(|| no_item(&self.id))?;
        self.agent
            .encrypt_secret(session, &owner, value, item.content_type)
    }

    fn set_secret(
        &self,
        secret: Secret,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<()> {
        let (value, content_type) = self.agent.decrypt_secret(secret, &sender(&header)?)?;
        self.agent.set_secret(&self.id, value, content_type)
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

fn session_input(algorithm: &str, input: OwnedValue) -> fdo::Result<Vec<u8>> {
    if algorithm == secret_service_protocol::ALGORITHM_PLAIN {
        let plain = String::try_from(input).map_err(|_| {
            fdo::Error::Failed("invalid plain Secret Service session input".to_owned())
        })?;
        if plain.is_empty() {
            Ok(Vec::new())
        } else {
            Err(fdo::Error::Failed(
                "plain Secret Service session input must be empty".to_owned(),
            ))
        }
    } else {
        Vec::<u8>::try_from(input)
            .map_err(|_| fdo::Error::Failed("invalid Secret Service DH public key".to_owned()))
    }
}

fn session_output(output: SessionOutput) -> fdo::Result<OwnedValue> {
    match output {
        SessionOutput::Plain => {
            OwnedValue::try_from(zbus::zvariant::Value::from(String::new())).map_err(failed)
        }
        SessionOutput::DhPublicKey(value) => {
            OwnedValue::try_from(zbus::zvariant::Value::from(value)).map_err(failed)
        }
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

#[cfg(all(test, feature = "hardware"))]
mod tests {
    use super::*;
    use crate::vault::VaultStore;
    use crate::{CallerIdentity, CallerPlatform, UnsealLeasePolicy, Vault};

    #[cfg(target_os = "linux")]
    use zbus::Proxy;

    fn agent() -> (tempfile::TempDir, Agent) {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unsealed = Vault::create_for_test(&root).unwrap();
        let store = VaultStore::open(root, unsealed).unwrap();
        let service =
            Arc::new(VaultService::new(store, 100, UnsealLeasePolicy::default()).unwrap());
        let caller = CallerIdentity::new(
            CallerPlatform::Linux,
            "uid:1000",
            "factorseal-secret-service-test",
            [0x33; 32],
            None,
        )
        .unwrap();
        service
            .authorize_namespace(
                &caller,
                NAMESPACE,
                [
                    GrantPermission::Get,
                    GrantPermission::Put,
                    GrantPermission::Delete,
                ],
                None,
                100,
            )
            .unwrap();
        let store = Store { service, caller };
        let agent = Agent::load(store).unwrap();
        (directory, agent)
    }

    #[test]
    fn item_metadata_and_secret_remain_in_sync_through_updates_and_delete() {
        let (_directory, agent) = agent();
        let agent = Arc::new(agent);
        let attributes = HashMap::from([("service".to_owned(), "example.test".to_owned())]);
        let (item, created) = agent
            .create_or_replace(
                "Example".to_owned(),
                attributes.clone(),
                b"first".to_vec(),
                "text/plain".to_owned(),
                false,
            )
            .unwrap();
        assert!(created);
        assert_eq!(
            agent.store.get(secret_item(&item.id)).unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(agent.all_items().unwrap(), vec![item.clone()]);

        agent
            .set_secret(
                &item.id,
                b"second".to_vec(),
                "application/octet-stream".to_owned(),
            )
            .unwrap();
        assert_eq!(
            agent.store.get(secret_item(&item.id)).unwrap(),
            Some(b"second".to_vec())
        );
        let updated = agent.item(&item.id).unwrap();
        assert_eq!(updated.content_type, "application/octet-stream");
        assert_eq!(updated.attributes, attributes);

        agent.delete_item(&item.id).unwrap();
        assert_eq!(agent.store.get(secret_item(&item.id)).unwrap(), None);
        assert!(agent.all_items().unwrap().is_empty());
        let index: Index = serde_json::from_slice(
            &agent
                .store
                .get(INDEX_ITEM)
                .unwrap()
                .expect("index is retained"),
        )
        .unwrap();
        assert!(index.items.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn session_bus_crud_uses_the_exported_secret_service_interfaces() {
        // Developers outside a desktop session, or with another Secret
        // Service already registered, can still run the unit suite. Linux CI
        // runs it under `dbus-run-session`, where this full exchange is
        // mandatory on an isolated bus.
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return;
        }

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (_directory, agent) = agent();
            let agent = Arc::new(agent);
            let Ok(server_connection) = Connection::session().await else {
                return;
            };
            if let Err(error) = server_connection
                .request_name_with_flags(BUS_NAME, zbus::fdo::RequestNameFlags::DoNotQueue.into())
                .await
            {
                if matches!(error, zbus::Error::NameTaken) {
                    return;
                }
                panic!("could not register the Secret Service test name: {error}");
            }
            let server = server_connection.object_server();
            server
                .at(
                    SERVICE_PATH,
                    Service {
                        agent: Arc::clone(&agent),
                    },
                )
                .await
                .unwrap();
            server
                .at(COLLECTION_PATH, Collection { agent })
                .await
                .unwrap();

            let client = Connection::session().await.unwrap();
            let service = Proxy::new(
                &client,
                BUS_NAME,
                SERVICE_PATH,
                "org.freedesktop.Secret.Service",
            )
            .await
            .unwrap();
            let input = OwnedValue::try_from(zbus::zvariant::Value::from(String::new())).unwrap();
            let (_output, session): (OwnedValue, OwnedObjectPath) = service
                .call("OpenSession", &("plain".to_owned(), input))
                .await
                .unwrap();

            let properties = HashMap::from([
                (
                    "org.freedesktop.Secret.Item.Label".to_owned(),
                    OwnedValue::try_from(zbus::zvariant::Value::from("Example")).unwrap(),
                ),
                (
                    "org.freedesktop.Secret.Item.Attributes".to_owned(),
                    OwnedValue::try_from(zbus::zvariant::Value::from(HashMap::from([(
                        "service".to_owned(),
                        "example.test".to_owned(),
                    )])))
                    .unwrap(),
                ),
            ]);
            let collection = Proxy::new(
                &client,
                BUS_NAME,
                COLLECTION_PATH,
                "org.freedesktop.Secret.Collection",
            )
            .await
            .unwrap();
            let (item, _prompt): (OwnedObjectPath, OwnedObjectPath) = collection
                .call(
                    "CreateItem",
                    &(
                        properties,
                        (
                            session.clone(),
                            Vec::<u8>::new(),
                            b"first".to_vec(),
                            "text/plain".to_owned(),
                        ),
                        false,
                    ),
                )
                .await
                .unwrap();
            let item_proxy = Proxy::new(
                &client,
                BUS_NAME,
                item.clone(),
                "org.freedesktop.Secret.Item",
            )
            .await
            .unwrap();
            let secret: Secret = item_proxy
                .call("GetSecret", &(session.clone(),))
                .await
                .unwrap();
            assert_eq!(secret.2, b"first");
            item_proxy
                .call::<_, _, ()>(
                    "SetSecret",
                    &((
                        session.clone(),
                        Vec::<u8>::new(),
                        b"second".to_vec(),
                        "application/octet-stream".to_owned(),
                    ),),
                )
                .await
                .unwrap();
            let secret: Secret = item_proxy.call("GetSecret", &(session,)).await.unwrap();
            assert_eq!(secret.2, b"second");
            let _prompt: OwnedObjectPath = item_proxy.call("Delete", &()).await.unwrap();
        });
    }
}

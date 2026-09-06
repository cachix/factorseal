//! D-Bus interface objects exposed by the Secret Service adapter.
//!
//! Every object holds the shared adapter state rather than a vault handle, so
//! the objects outlive seal cycles. Vault access goes through
//! [`Shared::agent`], which answers `IsLocked` while sealed.

use std::collections::HashMap;
use std::sync::Arc;

use secret_service_protocol::Session as ProtocolSession;
use zbus::object_server::{ObjectServer, SignalEmitter};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{fdo, interface};

use super::agent::Agent;
use super::{
    COLLECTION_PATH, DEFAULT_ALIAS_PATH, PROMPT_PREFIX, Properties, SESSION_PREFIX, Secret,
    SecretServiceError, Shared, failed, item_id, item_path, no_item, object_path, prompt_result,
    property_map, property_string, random_id, root_path, secret_item, sender, session_input,
    session_output,
};

pub(super) struct Service {
    pub(super) shared: Arc<Shared>,
}

pub(super) struct Collection {
    pub(super) shared: Arc<Shared>,
}

pub(super) struct Item {
    pub(super) shared: Arc<Shared>,
    pub(super) id: String,
}

/// One outstanding `Unlock` request, completed by the host on unseal or
/// dismissal.
pub(super) struct Prompt {
    pub(super) shared: Arc<Shared>,
    pub(super) path: String,
}

struct Session {
    shared: Arc<Shared>,
    path: String,
}

fn matching_items(
    agent: &Agent,
    attributes: &HashMap<String, String>,
) -> fdo::Result<Vec<OwnedObjectPath>> {
    agent
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

fn sealed() -> fdo::Error {
    fdo::Error::Failed("the FactorSeal vault is sealed".to_owned())
}

#[allow(clippy::needless_pass_by_value, clippy::unused_self)]
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
        self.shared
            .open_session(path.clone(), owner.clone(), session)?;
        let object_path = object_path(&path)?;
        if let Err(error) = server
            .at(
                path.clone(),
                Session {
                    shared: Arc::clone(&self.shared),
                    path: path.clone(),
                },
            )
            .await
        {
            // Registration failed after the key entered the session map.
            // Remove it immediately so failed opens cannot accumulate keys.
            let _ = self.shared.close_session(&path, &owner);
            return Err(failed(error));
        }
        Ok((session_output(output)?, object_path))
    }

    /// While sealed the index is unreadable, so nothing can be matched; the
    /// collection itself reports `Locked` and `Unlock` produces the prompt.
    #[zbus(out_args("unlocked", "locked"))]
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>)> {
        match self.shared.agent() {
            Ok(agent) => Ok((matching_items(&agent, &attributes)?, Vec::new())),
            Err(_) => Ok((Vec::new(), Vec::new())),
        }
    }

    /// Unsealed objects are already unlocked. Sealed ones need the host to
    /// unseal, which the returned prompt requests when a client runs it.
    #[zbus(out_args("unlocked", "prompt"))]
    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        if !self.shared.locked() {
            return Ok((objects, root_path()?));
        }
        let path = format!("{PROMPT_PREFIX}{}", random_id().map_err(failed)?);
        server
            .at(
                path.clone(),
                Prompt {
                    shared: Arc::clone(&self.shared),
                    path: path.clone(),
                },
            )
            .await
            .map_err(failed)?;
        self.shared.register_prompt(path.clone())?;
        Ok((Vec::new(), object_path(&path)?))
    }

    #[zbus(out_args("locked", "prompt"))]
    fn lock(
        &self,
        objects: Vec<OwnedObjectPath>,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        if let Ok(agent) = self.shared.agent() {
            agent.store.seal().map_err(failed)?;
        }
        Ok((objects, root_path()?))
    }

    #[zbus(out_args("secrets",))]
    fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<HashMap<OwnedObjectPath, Secret>, SecretServiceError> {
        let agent = self.shared.agent()?;
        let owner = sender(&header)?;
        let mut result = HashMap::new();
        for path in items {
            let id = item_id(path.as_str())?;
            let item = agent.item(id)?;
            let value = agent
                .store
                .get(secret_item(id))
                .map_err(failed)?
                .ok_or_else(|| no_item(id))?;
            result.insert(
                path,
                self.shared
                    .encrypt_secret(session.clone(), &owner, &value, item.content_type)?,
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

    #[zbus(signal)]
    pub(super) async fn collection_changed(
        emitter: &SignalEmitter<'_>,
        collection: OwnedObjectPath,
    ) -> zbus::Result<()>;
}

#[allow(clippy::needless_pass_by_value, clippy::unused_self)]
#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(out_args("results",))]
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> fdo::Result<Vec<OwnedObjectPath>> {
        match self.shared.agent() {
            Ok(agent) => matching_items(&agent, &attributes),
            Err(_) => Ok(Vec::new()),
        }
    }

    #[zbus(out_args("item", "prompt"))]
    async fn create_item(
        &self,
        properties: Properties,
        secret: Secret,
        replace: bool,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretServiceError> {
        let agent = self.shared.agent()?;
        let (value, content_type) = self.shared.decrypt_secret(secret, &sender(&header)?)?;
        let label = property_string(&properties, "org.freedesktop.Secret.Item.Label")?;
        let attributes = property_map(&properties, "org.freedesktop.Secret.Item.Attributes")?;
        let (item, created) =
            agent.create_or_replace(label, attributes, &value, content_type, replace)?;
        let path = item_path(&item.id)?;
        if created {
            server
                .at(
                    path.clone(),
                    Item {
                        shared: Arc::clone(&self.shared),
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
        match self.shared.agent() {
            Ok(agent) => agent
                .all_items()?
                .into_iter()
                .map(|item| item_path(&item.id))
                .collect(),
            Err(_) => Ok(Vec::new()),
        }
    }

    #[zbus(property)]
    fn label(&self) -> String {
        "Factorseal".to_owned()
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.shared.locked()
    }
}

#[allow(clippy::needless_pass_by_value, clippy::unused_self)]
#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(out_args("secret",))]
    fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Secret, SecretServiceError> {
        let agent = self.shared.agent()?;
        let owner = sender(&header)?;
        let item = agent.item(&self.id)?;
        let value = agent
            .store
            .get(secret_item(&self.id))
            .map_err(failed)?
            .ok_or_else(|| no_item(&self.id))?;
        Ok(self
            .shared
            .encrypt_secret(session, &owner, &value, item.content_type)?)
    }

    fn set_secret(
        &self,
        secret: Secret,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<(), SecretServiceError> {
        let agent = self.shared.agent()?;
        let (value, content_type) = self.shared.decrypt_secret(secret, &sender(&header)?)?;
        Ok(agent.set_secret(&self.id, &value, content_type)?)
    }

    #[zbus(out_args("prompt",))]
    async fn delete(
        &self,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<OwnedObjectPath, SecretServiceError> {
        let agent = self.shared.agent()?;
        agent.delete_item(&self.id)?;
        server
            .remove::<Item, _>(item_path(&self.id)?)
            .await
            .map_err(failed)?;
        Ok(root_path()?)
    }

    #[zbus(property)]
    fn label(&self) -> fdo::Result<String> {
        Ok(self.agent()?.item(&self.id)?.label)
    }

    #[zbus(property)]
    fn attributes(&self) -> fdo::Result<HashMap<String, String>> {
        Ok(self.agent()?.item(&self.id)?.attributes)
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.shared.locked()
    }

    #[zbus(property)]
    fn created(&self) -> fdo::Result<u64> {
        Ok(self.agent()?.item(&self.id)?.created)
    }

    #[zbus(property)]
    fn modified(&self) -> fdo::Result<u64> {
        Ok(self.agent()?.item(&self.id)?.modified)
    }
}

impl Item {
    fn agent(&self) -> fdo::Result<Arc<Agent>> {
        self.shared.agent().map_err(|_| sealed())
    }
}

#[allow(clippy::needless_pass_by_value, clippy::unused_self)]
#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<()> {
        self.shared.close_session(&self.path, &sender(&header)?)?;
        server
            .remove::<Session, _>(self.path.as_str())
            .await
            .map_err(failed)?;
        Ok(())
    }
}

#[allow(clippy::needless_pass_by_value, clippy::unused_self)]
#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    /// Ask the host to unseal. `Completed` follows from the host, either when
    /// the vault is published or when the host reports the prompt dismissed.
    fn prompt(&self, window_id: String) -> fdo::Result<()> {
        // The host raises its own window; a parent window hint is not used.
        drop(window_id);
        if !self.shared.prompt_pending(&self.path)? {
            return Err(fdo::Error::Failed(
                "Secret Service prompt already completed".to_owned(),
            ));
        }
        self.shared.prompter.request_unlock();
        Ok(())
    }

    async fn dismiss(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<()> {
        if self.shared.take_prompt(&self.path)? {
            Self::completed(&emitter, true, prompt_result(true)?)
                .await
                .map_err(failed)?;
        }
        server
            .remove::<Prompt, _>(self.path.as_str())
            .await
            .map_err(failed)?;
        Ok(())
    }

    #[zbus(signal)]
    pub(super) async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: OwnedValue,
    ) -> zbus::Result<()>;
}

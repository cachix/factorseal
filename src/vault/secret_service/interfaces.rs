//! D-Bus interface objects exposed by the Secret Service adapter.

use std::collections::HashMap;
use std::sync::Arc;

use secret_service_protocol::Session as ProtocolSession;
use zbus::object_server::ObjectServer;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{fdo, interface};

use super::agent::Agent;
use super::{
    COLLECTION_PATH, DEFAULT_ALIAS_PATH, Properties, SESSION_PREFIX, Secret, failed, item_id,
    item_path, no_item, object_path, property_map, property_string, random_id, root_path,
    secret_item, sender, session_input, session_output,
};

pub(super) struct Service {
    pub(super) agent: Arc<Agent>,
}

pub(super) struct Collection {
    pub(super) agent: Arc<Agent>,
}

pub(super) struct Item {
    pub(super) agent: Arc<Agent>,
    pub(super) id: String,
}

struct Session {
    agent: Arc<Agent>,
    path: String,
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
        self.agent
            .open_session(path.clone(), owner.clone(), session)?;
        let object_path = object_path(&path)?;
        if let Err(error) = server
            .at(
                path.clone(),
                Session {
                    agent: Arc::clone(&self.agent),
                    path: path.clone(),
                },
            )
            .await
        {
            // Registration failed after the key entered the session map.
            // Remove it immediately so failed opens cannot accumulate keys.
            let _ = self.agent.close_session(&path, &owner);
            return Err(failed(error));
        }
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
}

#[allow(clippy::needless_pass_by_value, clippy::unused_self)]
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
                .create_or_replace(label, attributes, &value, content_type, replace)?;
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

#[allow(clippy::needless_pass_by_value, clippy::unused_self)]
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
            .encrypt_secret(session, &owner, &value, item.content_type)
    }

    fn set_secret(
        &self,
        secret: Secret,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> fdo::Result<()> {
        let (value, content_type) = self.agent.decrypt_secret(secret, &sender(&header)?)?;
        self.agent.set_secret(&self.id, &value, content_type)
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

#[allow(clippy::needless_pass_by_value, clippy::unused_self)]
#[interface(name = "org.freedesktop.Secret.Session")]
impl Session {
    async fn close(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<()> {
        self.agent.close_session(&self.path, &sender(&header)?)?;
        server
            .remove::<Session, _>(self.path.as_str())
            .await
            .map_err(failed)?;
        Ok(())
    }
}

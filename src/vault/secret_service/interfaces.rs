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
    pub(super) objects: Vec<OwnedObjectPath>,
}

pub(super) struct Session {
    shared: Arc<Shared>,
    path: String,
}

async fn registered_items(
    shared: &Arc<Shared>,
    server: &ObjectServer,
) -> Result<Vec<super::agent::IndexItem>, SecretServiceError> {
    let items = shared.agent()?.all_items()?;
    for item in &items {
        server
            .at(
                item_path(&item.id)?,
                Item {
                    shared: Arc::clone(shared),
                    id: item.id.clone(),
                },
            )
            .await
            .map_err(failed)?;
    }
    Ok(items)
}

fn service_target(attributes: &HashMap<String, String>) -> String {
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

async fn matching_items(
    shared: &Arc<Shared>,
    server: &ObjectServer,
    attributes: &HashMap<String, String>,
    owner: &str,
) -> Result<Vec<OwnedObjectPath>, SecretServiceError> {
    if attributes.contains_key("service") {
        shared
            .authorized_agent(
                owner,
                &service_target(attributes),
                super::super::PermissionOperation::Get,
            )
            .await?;
    }
    let mut paths = Vec::new();
    for item in registered_items(shared, server).await? {
        if attributes
            .iter()
            .all(|(key, value)| item.attributes.get(key) == Some(value))
        {
            if !attributes.contains_key("service") {
                shared
                    .authorized_agent(
                        owner,
                        &service_target(&item.attributes),
                        super::super::PermissionOperation::Get,
                    )
                    .await?;
            }
            paths.push(item_path(&item.id)?);
        }
    }
    Ok(paths)
}

#[cfg(feature = "key-protection")]
async fn authorize_input_peer(shared: &Shared, owner: String) -> Result<(), SecretServiceError> {
    let store = shared.agent()?.store.clone();
    let response = tokio::task::spawn_blocking(move || {
        store.backend_request(super::super::VaultRequest::new(
            super::super::VaultAction::AuthorizeSecretInput { sender: owner },
        )?)
    })
    .await
    .map_err(failed)?
    .map_err(failed)?;
    response.check_delivery().map_err(failed)?;
    if response.result.is_err() {
        return Err(SecretServiceError::AccessDenied(
            "Only an authorized FactorSeal provider may receive secure IPC input".to_owned(),
        ));
    }
    Ok(())
}

async fn access_context(
    attributes: &HashMap<String, String>,
    header: &zbus::message::Header<'_>,
    connection: &zbus::Connection,
) -> super::SecretServiceAccessContext {
    let owner = header.sender().map(ToString::to_string).unwrap_or_default();
    let mut context = super::SecretServiceAccessContext {
        attributes: attributes
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
        sender: owner.clone(),
        ..Default::default()
    };
    if let Ok(bus) = fdo::DBusProxy::new(connection).await
        && let Ok(name) = zbus::names::BusName::try_from(owner.as_str())
        && let Ok(pid) = bus.get_connection_unix_process_id(name).await
    {
        context.process_id = Some(pid);
        context.executable = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        context.working_directory = std::fs::read_link(format!("/proc/{pid}/cwd")).ok();
        if attributes
            .get("service")
            .is_some_and(|service| service.starts_with("secretspec/"))
            && let Some(cwd) = context
                .working_directory
                .as_ref()
                .and_then(|cwd| std::fs::canonicalize(cwd).ok())
        {
            let folder = cwd
                .ancestors()
                .find(|folder| folder.join("secretspec.toml").is_file())
                .unwrap_or(&cwd);
            context
                .attributes
                .insert("base_dir".to_owned(), folder.display().to_string());
        }
    }
    context
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
        #[zbus(connection)] connection: &zbus::Connection,
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
        // The disconnect watcher may have removed the session while at()
        // was awaiting registration. Do not leave an orphan object behind.
        let alive = async {
            fdo::DBusProxy::new(connection)
                .await
                .map_err(failed)?
                .name_has_owner(zbus::names::BusName::try_from(owner.as_str()).map_err(failed)?)
                .await
        }
        .await;
        if !matches!(alive, Ok(true)) || self.shared.session(&object_path, &owner).is_err() {
            let _ = self.shared.close_session(&path, &owner);
            let _ = server.remove::<Session, _>(path.as_str()).await;
            return Err(failed("Secret Service client disconnected"));
        }
        Ok((session_output(output)?, object_path))
    }

    /// Ask the host to unlock the encrypted index before searching.
    #[zbus(out_args("unlocked", "locked"))]
    pub(super) async fn search_items(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(Vec<OwnedObjectPath>, Vec<OwnedObjectPath>), SecretServiceError> {
        let context = access_context(&attributes, &header, connection).await;
        if self.shared.locked() {
            self.shared.unlock_for_search(context.clone()).await?;
        }
        let result = matching_items(&self.shared, server, &attributes, &sender(&header)?).await;
        self.shared.prompter.finish_access(context);
        result.map(|items| (items, Vec::new()))
    }

    /// FactorSeal extension: unlock before retrying native IPC; grants are separate.
    async fn unlock_for_ipc(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), SecretServiceError> {
        self.shared
            .unlock_for_search(access_context(&attributes, &header, connection).await)
            .await
    }

    // zbus's generated property dispatcher still references a getter removed
    // by method-level cfg. Keep this getter and report disabled capabilities.
    #[zbus(property)]
    fn supports_secure_input(&self) -> bool {
        cfg!(feature = "key-protection") && self.shared.prompter.supports_input()
    }

    #[cfg(feature = "key-protection")]
    async fn input_for_ipc(
        &self,
        attributes: HashMap<String, String>,
        channel: zbus::zvariant::OwnedFd,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), SecretServiceError> {
        if !self.shared.prompter.supports_input() {
            return Err(SecretServiceError::NotSupported(
                "This host has no secure input UI".to_owned(),
            ));
        }
        let context = access_context(&attributes, &header, connection).await;
        if self.shared.locked() {
            self.shared.unlock_for_search(context.clone()).await?;
        }
        let owner = sender(&header)?;
        if let Err(error) = authorize_input_peer(&self.shared, owner.clone()).await {
            self.shared.prompter.finish_access(context);
            return Err(error);
        }
        let mut channel = std::os::unix::net::UnixStream::from(std::os::fd::OwnedFd::from(channel));
        channel
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .map_err(failed)?;
        channel
            .set_write_timeout(Some(std::time::Duration::from_secs(2)))
            .map_err(failed)?;
        let (mut channel, initial) = tokio::task::spawn_blocking(move || {
            let initial = crate::desktop_worker::receive::<super::super::WireSecret>(&mut channel);
            (channel, initial)
        })
        .await
        .map_err(failed)?;
        let value = self
            .shared
            .input_secret(context, initial.map_err(failed)?)
            .await?;
        authorize_input_peer(&self.shared, owner).await?;
        tokio::task::spawn_blocking(move || crate::desktop_worker::send(&mut channel, &value))
            .await
            .map_err(failed)?
            .map_err(failed)?;
        Ok(())
    }

    async fn finish_ipc_access(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) {
        self.shared
            .prompter
            .finish_access(access_context(&attributes, &header, connection).await);
    }

    /// Unsealed objects are already unlocked. Sealed ones need the host to
    /// unseal, which the returned prompt requests when a client runs it.
    #[zbus(out_args("unlocked", "prompt"))]
    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<(Vec<OwnedObjectPath>, OwnedObjectPath)> {
        if objects.is_empty() || !self.shared.locked() {
            return Ok((unlocked_objects(&self.shared, objects)?, root_path()?));
        }
        let objects: Vec<_> = objects
            .into_iter()
            .filter(|path| {
                matches!(path.as_str(), COLLECTION_PATH | DEFAULT_ALIAS_PATH)
                    || item_id(path.as_str()).is_ok()
            })
            .collect();
        if objects.is_empty() {
            return Ok((Vec::new(), root_path()?));
        }
        let path = format!("{PROMPT_PREFIX}{}", random_id().map_err(failed)?);
        server
            .at(
                path.clone(),
                Prompt {
                    shared: Arc::clone(&self.shared),
                    path: path.clone(),
                    objects,
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
    async fn get_secrets(
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
            let agent = self
                .shared
                .authorized_agent(
                    &owner,
                    &service_target(&item.attributes),
                    super::super::PermissionOperation::Get,
                )
                .await?;
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
    pub(super) async fn search_items(
        &self,
        attributes: HashMap<String, String>,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<Vec<OwnedObjectPath>, SecretServiceError> {
        let context = access_context(&attributes, &header, connection).await;
        if self.shared.locked() {
            self.shared.unlock_for_search(context.clone()).await?;
        }
        let result = matching_items(&self.shared, server, &attributes, &sender(&header)?).await;
        self.shared.prompter.finish_access(context);
        result
    }

    #[zbus(out_args("item", "prompt"))]
    async fn create_item(
        &self,
        properties: Properties,
        secret: Secret,
        replace: bool,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), SecretServiceError> {
        let label = property_string(&properties, "org.freedesktop.Secret.Item.Label")?;
        let attributes = property_map(&properties, "org.freedesktop.Secret.Item.Attributes")?;
        let (value, content_type) = self.shared.decrypt_secret(secret, &sender(&header)?)?;
        let context = access_context(&attributes, &header, connection).await;
        let (agent, value) = if self.shared.prompter.supports_input() {
            let value = self
                .shared
                .input_secret(
                    context.clone(),
                    super::super::WireSecret::new(value.to_vec()).map_err(failed)?,
                )
                .await?;
            (self.shared.agent()?, value)
        } else {
            let agent = self
                .shared
                .authorized_agent(
                    &sender(&header)?,
                    &service_target(&attributes),
                    super::super::PermissionOperation::Put,
                )
                .await?;
            (
                agent,
                super::super::WireSecret::new(value.to_vec()).map_err(failed)?,
            )
        };
        let (item, created) =
            agent.create_or_replace(label, attributes, value.expose(), content_type, replace)?;
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
        self.shared.prompter.finish_access(context);
        Ok((path, root_path()?))
    }

    #[zbus(property)]
    async fn items(
        &self,
        #[zbus(header)] header: Option<zbus::message::Header<'_>>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<Vec<OwnedObjectPath>> {
        let Some(header) = header else {
            return Ok(Vec::new());
        };
        if self.shared.locked() {
            return Ok(Vec::new());
        }
        matching_items(&self.shared, server, &HashMap::new(), &sender(&header)?)
            .await
            .map_err(failed)
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
    async fn get_secret(
        &self,
        session: OwnedObjectPath,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> Result<Secret, SecretServiceError> {
        let agent = self
            .authorized_agent(&header, super::super::PermissionOperation::Get)
            .await?;
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

    async fn set_secret(
        &self,
        secret: Secret,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> Result<(), SecretServiceError> {
        let agent = self.shared.agent()?;
        let item = agent.item(&self.id)?;
        let context = access_context(&item.attributes, &header, connection).await;
        let (value, content_type) = self.shared.decrypt_secret(secret, &sender(&header)?)?;
        let (agent, value) = if self.shared.prompter.supports_input() {
            let value = self
                .shared
                .input_secret(
                    context.clone(),
                    super::super::WireSecret::new(value.to_vec()).map_err(failed)?,
                )
                .await?;
            (self.shared.agent()?, value)
        } else {
            let agent = self
                .authorized_agent(&header, super::super::PermissionOperation::Put)
                .await?;
            (
                agent,
                super::super::WireSecret::new(value.to_vec()).map_err(failed)?,
            )
        };
        let result = agent.set_secret(&self.id, value.expose(), content_type);
        self.shared.prompter.finish_access(context);
        Ok(result?)
    }

    #[zbus(out_args("prompt",))]
    async fn delete(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> Result<OwnedObjectPath, SecretServiceError> {
        let agent = self
            .authorized_agent(&header, super::super::PermissionOperation::Delete)
            .await?;
        agent.delete_item(&self.id)?;
        server
            .remove::<Item, _>(item_path(&self.id)?)
            .await
            .map_err(failed)?;
        Ok(root_path()?)
    }

    #[zbus(property)]
    async fn label(
        &self,
        #[zbus(header)] header: Option<zbus::message::Header<'_>>,
    ) -> fdo::Result<String> {
        let Some(header) = header else {
            return Ok(String::new());
        };
        Ok(self
            .authorized_agent(&header, super::super::PermissionOperation::Get)
            .await
            .map_err(failed)?
            .item(&self.id)?
            .label)
    }

    #[zbus(property)]
    async fn attributes(
        &self,
        #[zbus(header)] header: Option<zbus::message::Header<'_>>,
    ) -> fdo::Result<HashMap<String, String>> {
        let Some(header) = header else {
            return Ok(HashMap::new());
        };
        Ok(self
            .authorized_agent(&header, super::super::PermissionOperation::Get)
            .await
            .map_err(failed)?
            .item(&self.id)?
            .attributes)
    }

    #[zbus(property)]
    fn locked(&self) -> bool {
        self.shared.locked()
    }

    #[zbus(property)]
    async fn created(
        &self,
        #[zbus(header)] header: Option<zbus::message::Header<'_>>,
    ) -> fdo::Result<u64> {
        let Some(header) = header else {
            return Ok(0);
        };
        Ok(self
            .authorized_agent(&header, super::super::PermissionOperation::Get)
            .await
            .map_err(failed)?
            .item(&self.id)?
            .created)
    }

    #[zbus(property)]
    async fn modified(
        &self,
        #[zbus(header)] header: Option<zbus::message::Header<'_>>,
    ) -> fdo::Result<u64> {
        let Some(header) = header else {
            return Ok(0);
        };
        Ok(self
            .authorized_agent(&header, super::super::PermissionOperation::Get)
            .await
            .map_err(failed)?
            .item(&self.id)?
            .modified)
    }
}

impl Item {
    async fn authorized_agent(
        &self,
        header: &zbus::message::Header<'_>,
        operation: super::super::PermissionOperation,
    ) -> Result<Arc<Agent>, SecretServiceError> {
        let item = self.shared.agent()?.item(&self.id)?;
        self.shared
            .authorized_agent(
                &sender(header)?,
                &service_target(&item.attributes),
                operation,
            )
            .await
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
    async fn prompt(
        &self,
        window_id: String,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<()> {
        // The host raises its own window; a parent window hint is not used.
        drop(window_id);
        if let Some(dismissed) = self.shared.invoke_prompt(&self.path)? {
            Self::completed(&emitter, dismissed, self.result(dismissed)?)
                .await
                .map_err(failed)?;
            server
                .remove::<Prompt, _>(self.path.as_str())
                .await
                .map_err(failed)?;
        } else {
            self.shared.prompter.request_unlock();
        }
        Ok(())
    }

    async fn dismiss(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        #[zbus(object_server)] server: &ObjectServer,
    ) -> fdo::Result<()> {
        if self.shared.take_prompt(&self.path)? {
            Self::completed(&emitter, true, self.result(true)?)
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

/// Return only requested objects that actually exist in the published vault.
fn unlocked_objects(
    shared: &Shared,
    objects: Vec<OwnedObjectPath>,
) -> fdo::Result<Vec<OwnedObjectPath>> {
    let Ok(agent) = shared.agent() else {
        return Ok(Vec::new());
    };
    let ids = agent.item_ids().map_err(failed)?;
    Ok(objects
        .into_iter()
        .filter(|path| {
            matches!(path.as_str(), COLLECTION_PATH | DEFAULT_ALIAS_PATH)
                || item_id(path.as_str()).is_ok_and(|id| ids.iter().any(|existing| existing == id))
        })
        .collect())
}

impl Prompt {
    pub(super) fn result(&self, dismissed: bool) -> fdo::Result<OwnedValue> {
        let objects = if dismissed {
            Vec::new()
        } else {
            unlocked_objects(&self.shared, self.objects.clone())?
        };
        prompt_result(dismissed, objects)
    }
}

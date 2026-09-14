//! System-bus secret agent. Only the current NetworkManager owner can invoke it.
//! Secrets live in the vault worker; the adapter retains no credential cache.

use std::collections::{BTreeMap, HashMap};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use network_manager_protocol::{self as protocol, GetSecretsFlags};
use tokio::sync::oneshot;
use zbus::{
    Connection, fdo,
    message::Header,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

use super::{SecretServiceAccessContext, SecretServiceError, Shared, agent::Store};
use crate::vault::{
    VaultAction, VaultMutation, VaultRequest, VaultResponseBody, WireSecret, WireSecretAddress,
};

pub(super) mod migration;
mod profile;
use profile::{NAME_FIELD, NAMESPACE, PROPERTIES, Profile};

type Settings = protocol::Settings<OwnedValue>;
const IDENTIFIER: &str = "dev.factorseal.NetworkManager";

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.NetworkManager.SecretAgent")]
enum Error {
    Failed(String),
    PermissionDenied(String),
    InvalidConnection(String),
    UserCanceled(String),
    AgentCanceled(String),
    NoSecrets(String),
}

impl Error {
    fn failed() -> Self {
        Self::Failed("Wi-Fi vault operation failed".into())
    }
    fn invalid() -> Self {
        Self::InvalidConnection("Invalid Wi-Fi credentials or profile".into())
    }
    fn no_secrets() -> Self {
        Self::NoSecrets("Wi-Fi credentials are unavailable".into())
    }
}

impl From<SecretServiceError> for Error {
    fn from(error: SecretServiceError) -> Self {
        match error {
            SecretServiceError::AccessDenied(_) | SecretServiceError::Cancelled(_) => {
                Self::UserCanceled("Wi-Fi request dismissed".into())
            }
            SecretServiceError::IsLocked(_) => Self::no_secrets(),
            _ => Self::failed(),
        }
    }
}

struct Pending {
    path: String,
    setting: String,
    cancel: oneshot::Sender<()>,
}

#[derive(Default)]
struct Requests {
    next: AtomicU64,
    pending: Mutex<HashMap<u64, Pending>>,
}

struct RequestGuard {
    requests: Arc<Requests>,
    id: u64,
    shared: Arc<Shared>,
    context: SecretServiceAccessContext,
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.requests.pending.lock() {
            pending.remove(&self.id);
        }
        self.shared.prompter.finish_access(self.context.clone());
    }
}

impl Requests {
    fn cancel(&self, path: Option<(&str, &str)>) {
        if let Ok(mut pending) = self.pending.lock() {
            let ids: Vec<_> = pending
                .iter()
                .filter(|(_, request)| {
                    path.is_none_or(|(path, setting)| {
                        request.path == path && request.setting == setting
                    })
                })
                .map(|(id, _)| *id)
                .collect();
            for id in ids {
                if let Some(request) = pending.remove(&id) {
                    let _ = request.cancel.send(());
                }
            }
        }
    }
}

struct Agent {
    shared: Arc<Shared>,
    requests: Arc<Requests>,
}

/// Authenticate against the bus daemon on every call, never against caller
/// supplied connection metadata or a cached process name.
async fn authenticate(connection: &Connection, header: &Header<'_>) -> Result<String, Error> {
    let sender = header
        .sender()
        .ok_or_else(|| Error::PermissionDenied("Missing sender".into()))?;
    let bus = fdo::DBusProxy::new(connection)
        .await
        .map_err(|_| Error::failed())?;
    let owner = bus
        .get_name_owner(protocol::BUS_NAME.try_into().map_err(|_| Error::failed())?)
        .await
        .map_err(|_| Error::PermissionDenied("NetworkManager is unavailable".into()))?;
    if sender.as_str() != owner.as_str() {
        return Err(Error::PermissionDenied(
            "Only NetworkManager may request Wi-Fi credentials".into(),
        ));
    }
    Ok(sender.to_string())
}

async fn call(store: Store, action: VaultAction) -> Result<VaultResponseBody, Error> {
    tokio::task::spawn_blocking(move || {
        let response = store
            .backend_request(VaultRequest::new(action).map_err(|_| Error::failed())?)
            .map_err(|_| Error::failed())?;
        response.check_delivery().map_err(|_| Error::no_secrets())?;
        response.result.map_err(|_| Error::failed())
    })
    .await
    .map_err(|_| Error::failed())?
}

async fn read(store: Store, address: WireSecretAddress) -> Result<Option<WireSecret>, Error> {
    match call(
        store,
        VaultAction::Get {
            namespace: NAMESPACE.to_vec(),
            address,
        },
    )
    .await?
    {
        VaultResponseBody::Secret { value } => Ok(value),
        _ => Err(Error::failed()),
    }
}

async fn mutate(store: Store, mutations: Vec<VaultMutation>) -> Result<(), Error> {
    if mutations.is_empty() {
        return Ok(());
    }
    match call(
        store,
        VaultAction::Mutate {
            namespace: NAMESPACE.to_vec(),
            mutations,
        },
    )
    .await?
    {
        VaultResponseBody::Mutated => Ok(()),
        _ => Err(Error::failed()),
    }
}

fn string_variant(value: &str) -> OwnedValue {
    OwnedValue::from(zbus::zvariant::Str::from(value.to_owned()))
}

async fn existing_value(
    store: &Store,
    profile: &Profile,
    credential: &profile::Credential,
    flags: GetSecretsFlags,
) -> Result<Option<WireSecret>, Error> {
    if !flags.allows_stored_secrets() {
        return Ok(None);
    }
    let property = credential.property;
    if credential.flags.agent_may_save()
        && let Some(value) = read(store.clone(), property.address(&profile.uuid)).await?
        && property
            .validate(&profile.key_management, value.expose())
            .is_ok()
    {
        return Ok(Some(value));
    }
    // NM may include system-owned secrets alongside the requested agent-owned
    // ones. Use those for this reply without taking ownership of their storage.
    if !credential.flags.contains(protocol::SecretFlags::NOT_SAVED)
        && let Some(supplied) = &credential.supplied
        && property
            .validate(&profile.key_management, supplied.expose())
            .is_ok()
    {
        return Ok(Some(
            WireSecret::new(supplied.expose().to_vec()).map_err(|_| Error::failed())?,
        ));
    }
    Ok(None)
}

impl Agent {
    fn check_generation(&self, uuid: &str, generation: u64) -> Result<(), Error> {
        if self
            .shared
            .wifi_migrations
            .lock()
            .map_err(|_| Error::failed())?
            .get(uuid)
            .is_some_and(|(changed, _)| *changed > generation)
        {
            return Err(Error::AgentCanceled(
                "Wi-Fi storage changed; retry the connection".into(),
            ));
        }
        Ok(())
    }
    fn check_migration(&self, uuid: &str) -> Result<(), Error> {
        if self
            .shared
            .wifi_migrations
            .lock()
            .map_err(|_| Error::failed())?
            .get(uuid)
            .is_some_and(|(_, active)| *active)
        {
            return Err(Error::no_secrets());
        }
        Ok(())
    }
    async fn store(
        &self,
        context: SecretServiceAccessContext,
        interactive: bool,
    ) -> Result<Store, Error> {
        if self.shared.locked() {
            if !interactive {
                return Err(Error::no_secrets());
            }
            self.shared.unlock_for_search(context).await?;
        }
        Ok(self.shared.agent()?.store.clone())
    }

    async fn get(
        &self,
        profile: Profile,
        flags: GetSecretsFlags,
        context: SecretServiceAccessContext,
        generation: u64,
    ) -> Result<Settings, Error> {
        let store = self
            .store(context.clone(), flags.allows_interaction())
            .await?;
        let mut result = BTreeMap::new();
        let mut writes = Vec::new();
        for credential in &profile.credentials {
            let property = credential.property;
            if !credential.flags.agent_may_save() {
                writes.push(VaultMutation::Delete {
                    address: property.address(&profile.uuid),
                });
            }
            let mut value = existing_value(&store, &profile, credential, flags).await?;
            if value.is_none() && credential.needed {
                if !flags.allows_interaction()
                    || !self.shared.prompter.supports_input()
                    || property.is_raw()
                {
                    return Err(Error::no_secrets());
                }
                let mut input_context = context.clone();
                input_context
                    .attributes
                    .insert("secret".into(), property.label().into());
                let entered = self
                    .shared
                    .input_secret(
                        input_context,
                        WireSecret::new(Vec::new()).map_err(|_| Error::failed())?,
                    )
                    .await?;
                property.validate(&profile.key_management, entered.expose())?;
                value = Some(entered);
                if credential.flags.agent_may_save() {
                    writes.push(VaultMutation::Put {
                        address: property.address(&profile.uuid),
                        value: WireSecret::new(
                            value.as_ref().ok_or_else(Error::failed)?.expose().to_vec(),
                        )
                        .map_err(|_| Error::failed())?,
                        evict_at: None,
                    });
                }
            }
            if let Some(value) = value {
                let variant = if property.is_raw() {
                    OwnedValue::try_from(Value::from(value.expose().to_vec()))
                        .map_err(|_| Error::failed())?
                } else {
                    string_variant(
                        std::str::from_utf8(value.expose()).map_err(|_| Error::invalid())?,
                    )
                };
                result.insert(property.name().to_owned(), variant);
            }
        }
        if result.is_empty() {
            return Err(Error::no_secrets());
        }
        if writes
            .iter()
            .any(|write| matches!(write, VaultMutation::Put { .. }))
        {
            writes.push(name_mutation(&profile)?);
        } else if profile
            .credentials
            .iter()
            .all(|credential| !credential.flags.agent_may_save())
        {
            writes.push(VaultMutation::Delete {
                address: WireSecretAddress::new(&profile.uuid, Some(NAME_FIELD.into())),
            });
        }
        let _write = self.shared.wifi_writes.lock().await;
        self.check_migration(&profile.uuid)?;
        self.check_generation(&profile.uuid, generation)?;
        mutate(store, writes).await?;
        // Do not deliver credentials if the desktop sealed while a prompt or
        // vault operation was pending. The backend also enforces delivery expiry.
        self.shared.agent()?;
        result.insert("name".into(), string_variant(profile.setting));
        Ok(BTreeMap::from([(profile.setting.to_owned(), result)]))
    }
}

fn name_mutation(profile: &Profile) -> Result<VaultMutation, Error> {
    Ok(VaultMutation::Put {
        address: WireSecretAddress::new(&profile.uuid, Some(NAME_FIELD.into())),
        value: WireSecret::new(profile.label.as_bytes().to_vec()).map_err(|_| Error::failed())?,
        evict_at: None,
    })
}

// D-Bus dispatch owns these arguments and requires the protocol method shape.
#[allow(clippy::needless_pass_by_value)]
#[zbus::interface(name = "org.freedesktop.NetworkManager.SecretAgent")]
impl Agent {
    #[allow(clippy::too_many_arguments)]
    async fn get_secrets(
        &self,
        connection: Settings,
        connection_path: OwnedObjectPath,
        setting_name: String,
        hints: Vec<String>,
        flags: u32,
        #[zbus(connection)] bus: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<Settings, Error> {
        let generation = self.shared.wifi_generation.load(Ordering::SeqCst);
        let sender = authenticate(bus, &header).await?;
        let profile = Profile::parse(&connection, &hints)?;
        self.check_migration(&profile.uuid)?;
        if setting_name != profile.setting {
            return Err(Error::no_secrets());
        }
        let id = self.requests.next.fetch_add(1, Ordering::Relaxed);
        let mut context = SecretServiceAccessContext {
            sender,
            attributes: BTreeMap::from([
                ("project".into(), profile.label.clone()),
                ("service".into(), "Wi-Fi passwords".into()),
                ("secret".into(), "Wi-Fi credentials".into()),
                ("factorseal_request_id".into(), format!("wifi-{id}")),
            ]),
            ..Default::default()
        };
        if let Ok(proxy) = fdo::DBusProxy::new(bus).await
            && let Ok(name) = context.sender.as_str().try_into()
            && let Ok(pid) = proxy.get_connection_unix_process_id(name).await
        {
            context.process_id = Some(pid);
            context.executable = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        }
        let (cancel, canceled) = oneshot::channel();
        {
            let mut pending = self.requests.pending.lock().map_err(|_| Error::failed())?;
            if pending.len() >= 64 {
                return Err(Error::failed());
            }
            pending.insert(
                id,
                Pending {
                    path: connection_path.to_string(),
                    setting: setting_name,
                    cancel,
                },
            );
        }
        let _guard = RequestGuard {
            requests: Arc::clone(&self.requests),
            id,
            shared: Arc::clone(&self.shared),
            context: context.clone(),
        };
        let result = tokio::select! {
            biased;
            _ = canceled => Err(Error::AgentCanceled("NetworkManager canceled the request".into())),
            result = tokio::time::timeout(Duration::from_mins(2), self.get(profile, GetSecretsFlags::from_bits_retain(flags), context, generation)) => {
                result.unwrap_or_else(|_| Err(Error::AgentCanceled("Wi-Fi request timed out".into())))
            }
        }?;
        authenticate(bus, &header).await?;
        Ok(result)
    }

    async fn cancel_get_secrets(
        &self,
        connection_path: OwnedObjectPath,
        setting_name: String,
        #[zbus(connection)] bus: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), Error> {
        authenticate(bus, &header).await?;
        self.requests
            .cancel(Some((connection_path.as_str(), &setting_name)));
        Ok(())
    }

    async fn save_secrets(
        &self,
        connection: Settings,
        connection_path: OwnedObjectPath,
        #[zbus(connection)] bus: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), Error> {
        let generation = self.shared.wifi_generation.load(Ordering::SeqCst);
        let sender = authenticate(bus, &header).await?;
        let _ = connection_path;
        let profile = Profile::parse(&connection, &[])?;
        // SaveSecrets has no interaction flags. A sealed vault cannot accept a
        // background write; NetworkManager gets a failure instead of false success.
        let store = self
            .store(
                SecretServiceAccessContext {
                    sender,
                    ..Default::default()
                },
                false,
            )
            .await?;
        let mut writes = Vec::new();
        for credential in &profile.credentials {
            if !credential.flags.agent_may_save() || credential.supplied.is_none() {
                writes.push(VaultMutation::Delete {
                    address: credential.property.address(&profile.uuid),
                });
            } else if let Some(value) = &credential.supplied {
                credential
                    .property
                    .validate(&profile.key_management, value.expose())?;
                writes.push(VaultMutation::Put {
                    address: credential.property.address(&profile.uuid),
                    value: WireSecret::new(value.expose().to_vec()).map_err(|_| Error::failed())?,
                    evict_at: None,
                });
            }
        }
        // A changed security mode must not leave credentials from the old mode.
        writes.extend(
            PROPERTIES
                .into_iter()
                .filter(|property| property.setting() != profile.setting)
                .map(|property| VaultMutation::Delete {
                    address: property.address(&profile.uuid),
                }),
        );
        if writes
            .iter()
            .any(|write| matches!(write, VaultMutation::Put { .. }))
        {
            writes.push(name_mutation(&profile)?);
        } else {
            writes.push(VaultMutation::Delete {
                address: WireSecretAddress::new(&profile.uuid, Some(NAME_FIELD.into())),
            });
        }
        let _write = self.shared.wifi_writes.lock().await;
        // NM sends SaveSecrets asynchronously after Update2. Queue those
        // notifications behind migration, but reject an older snapshot.
        self.check_generation(&profile.uuid, generation)?;
        mutate(store, writes).await
    }

    async fn delete_secrets(
        &self,
        connection: Settings,
        connection_path: OwnedObjectPath,
        #[zbus(connection)] bus: &Connection,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), Error> {
        let generation = self.shared.wifi_generation.load(Ordering::SeqCst);
        let sender = authenticate(bus, &header).await?;
        let uuid = Profile::uuid(&connection)?;
        // A late response to an earlier prompt must not recreate a deleted
        // connection's credentials. The deletion covers both security modes.
        for setting in [protocol::WIFI_SECURITY_SETTING, protocol::EAP_SETTING] {
            self.requests
                .cancel(Some((connection_path.as_str(), setting)));
        }
        let store = self
            .store(
                SecretServiceAccessContext {
                    sender,
                    ..Default::default()
                },
                false,
            )
            .await?;
        let mut deletes: Vec<_> = PROPERTIES
            .into_iter()
            .map(|property| VaultMutation::Delete {
                address: property.address(&uuid),
            })
            .collect();
        deletes.push(VaultMutation::Delete {
            address: WireSecretAddress::new(&uuid, Some(NAME_FIELD.into())),
        });
        let _write = self.shared.wifi_writes.lock().await;
        self.check_generation(&uuid, generation)?;
        mutate(store, deletes).await
    }
}

/// Register again after a daemon or system-bus restart. Registration is tied
/// to this connection; dropping it unregisters without leaving a service behind.
#[cfg(not(test))]
pub(super) async fn run(shared: Arc<Shared>) {
    loop {
        let requests = Arc::new(Requests::default());
        if let Ok(connection) = Connection::system().await {
            let _ = serve_on(connection, Arc::clone(&shared), Arc::clone(&requests)).await;
        }
        requests.cancel(None);
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

async fn serve_on(
    connection: Connection,
    shared: Arc<Shared>,
    requests: Arc<Requests>,
) -> Result<(), zbus::Error> {
    connection
        .object_server()
        .at(
            protocol::SECRET_AGENT_PATH,
            Agent {
                shared: Arc::clone(&shared),
                requests: Arc::clone(&requests),
            },
        )
        .await?;
    let bus = fdo::DBusProxy::new(&connection).await?;
    let mut registered: Option<String> = None;
    let mut registration_error_reported = false;
    let mut was_locked = shared.locked();
    loop {
        let owner = match bus.get_name_owner(protocol::BUS_NAME.try_into()?).await {
            Ok(owner) => Some(owner.to_string()),
            Err(fdo::Error::NameHasNoOwner(_)) => None,
            Err(error) => return Err(error.into()),
        };
        if owner != registered {
            requests.cancel(None);
            registered = None;
            if let Some(owner) = owner {
                let manager = zbus::Proxy::new(
                    &connection,
                    owner.clone(),
                    protocol::AGENT_MANAGER_PATH,
                    protocol::AGENT_MANAGER_INTERFACE,
                )
                .await?;
                match manager
                    .call::<_, _, ()>(
                        "RegisterWithCapabilities",
                        &(IDENTIFIER, protocol::AgentCapabilities::NONE.bits()),
                    )
                    .await
                {
                    Ok(()) => {
                        registered = Some(owner);
                        registration_error_reported = false;
                    }
                    Err(error) if !registration_error_reported => {
                        eprintln!("FactorSeal: Wi-Fi agent registration failed; retrying: {error}");
                        registration_error_reported = true;
                    }
                    Err(_) => {}
                }
            }
        }
        let locked = shared.locked();
        if locked && !was_locked {
            requests.cancel(None);
        }
        was_locked = locked;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

#[cfg(all(test, feature = "vault"))]
mod tests;

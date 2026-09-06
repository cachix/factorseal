//! Linux `org.freedesktop.secrets` adapter backed by the live Factorseal vault.
//!
//! The adapter is deliberately part of the unsealed vault process: it has no
//! database access of its own and disappears as soon as the vault seals.  The
//! session bus already authenticates peers as the current desktop user, which
//! is the same boundary provided by the other Secret Service implementations.

// zbus interface methods must own decoded D-Bus arguments, including headers
// and object paths; changing these signatures to references breaks dispatch.

use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secret_service_protocol::{Session as ProtocolSession, SessionOutput};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{Connection, fdo};
use zeroize::Zeroizing;

use super::linux::linux_caller_identity_for_executable;
use super::{GrantPermission, VaultError, VaultResult, VaultService};

mod agent;
mod interfaces;

use agent::{Agent, NAMESPACE, Store};
#[cfg(test)]
use agent::{INDEX_ITEM, Index};
use interfaces::{Collection, Item, Service};

const BUS_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/factorseal";
const DEFAULT_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";
const ITEM_PREFIX: &str = "/org/freedesktop/secrets/collection/factorseal/";
const SESSION_PREFIX: &str = "/org/freedesktop/secrets/session/";
const MAX_SESSIONS: usize = 1024;
const TAKEOVER_POLL: Duration = Duration::from_secs(1);

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
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            VaultError::Protocol(format!("could not start Secret Service runtime: {error}"))
        })?;
    runtime.block_on(async move {
        let connection = Connection::session().await.map_err(dbus_error)?;
        let caller =
            crate::timing::result("secret_service_startup", "identify_executable", || {
                let executable = std::env::current_exe().map_err(|error| {
                    VaultError::Protocol(format!(
                        "could not resolve Factorseal executable: {error}"
                    ))
                })?;
                linux_caller_identity_for_executable(executable)
            })?;
        crate::timing::result("secret_service_startup", "authorize_namespace", || {
            service.authorize_secret_service_namespace(
                &caller,
                NAMESPACE,
                [
                    GrantPermission::Get,
                    GrantPermission::Put,
                    GrantPermission::Delete,
                    GrantPermission::Seal,
                ],
                unix_time(),
            )
        })?;
        let store = Store {
            service: Arc::clone(&service),
            caller,
        };
        let agent = Arc::new(crate::timing::result(
            "secret_service_startup",
            "load_agent",
            || Agent::load(store),
        )?);
        let started = std::time::Instant::now();
        let claimed = claim_secret_service_name(&connection, TAKEOVER_POLL, || {
            Ok(stopping.load(Ordering::Acquire) || service.expire_if_needed(unix_time())?)
        })
        .await;
        crate::timing::record_result("secret_service_startup", "claim_name", started, &claimed);
        if !claimed? {
            return Ok(());
        }
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

impl Agent {
    fn open_session(
        &self,
        path: String,
        owner: String,
        session: ProtocolSession,
    ) -> fdo::Result<()> {
        let mut sessions = self.sessions.lock().map_err(poisoned)?;
        if sessions.len() >= MAX_SESSIONS {
            return Err(fdo::Error::LimitsExceeded(
                "too many open Secret Service sessions".to_owned(),
            ));
        }
        sessions.insert(path, SessionState { owner, session });
        Ok(())
    }

    fn close_session(&self, path: &str, owner: &str) -> fdo::Result<()> {
        let mut sessions = self.sessions.lock().map_err(poisoned)?;
        match sessions.get(path) {
            Some(session) if session.owner == owner => {
                sessions.remove(path);
                Ok(())
            }
            _ => Err(fdo::Error::Failed(
                "Secret Service session belongs to another client".to_owned(),
            )),
        }
    }

    fn session(&self, path: &OwnedObjectPath, owner: &str) -> fdo::Result<ProtocolSession> {
        match self.sessions.lock().map_err(poisoned)?.get(path.as_str()) {
            Some(session) if session.owner == owner => Ok(session.session.clone()),
            _ => Err(fdo::Error::Failed(
                "invalid Secret Service session".to_owned(),
            )),
        }
    }

    fn decrypt_secret(
        &self,
        secret: Secret,
        owner: &str,
    ) -> fdo::Result<(Zeroizing<Vec<u8>>, String)> {
        let (session, parameters, value, content_type) = secret;
        // In a plain Secret Service session `value` is plaintext. Take
        // zeroizing ownership immediately after zbus hands it to us.
        let value = Zeroizing::new(value);
        let value = self
            .session(&session, owner)?
            .decrypt(&parameters, &value)
            .map_err(failed)?;
        Ok((value, content_type))
    }

    fn encrypt_secret(
        &self,
        session: OwnedObjectPath,
        owner: &str,
        value: &Zeroizing<Vec<u8>>,
        content_type: String,
    ) -> fdo::Result<Secret> {
        let value = self
            .session(&session, owner)?
            .encrypt(value)
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
#[allow(clippy::needless_pass_by_value)]
fn dbus_error(error: zbus::Error) -> VaultError {
    VaultError::Protocol(format!("Secret Service D-Bus error: {error}"))
}

fn secret_service_name_claimed<T>(result: Result<T, zbus::Error>) -> VaultResult<bool> {
    match result {
        Ok(_) => Ok(true),
        Err(zbus::Error::NameTaken) => Ok(false),
        Err(error) => Err(dbus_error(error)),
    }
}
/// Claim the Secret Service name, taking it over from a previous provider once
/// that provider releases it.
///
/// Another Secret Service (gnome-keyring, KWallet, or a second FactorSeal
/// instance) may still own `org.freedesktop.secrets` when the vault unseals.
/// Giving up at that point left the name unowned for the rest of this process
/// once the other provider exited or crashed, while the desktop activation
/// helper kept waiting on this process to publish it. Returns `false` when
/// `should_stop` reports that the vault sealed or the service is stopping
/// before the name became available.
async fn claim_secret_service_name(
    connection: &Connection,
    poll: Duration,
    mut should_stop: impl FnMut() -> VaultResult<bool>,
) -> VaultResult<bool> {
    let bus = fdo::DBusProxy::new(connection).await.map_err(dbus_error)?;
    let name = zbus::names::BusName::try_from(BUS_NAME)
        .map_err(|error| VaultError::Protocol(format!("invalid Secret Service name: {error}")))?;
    let mut announced = false;
    loop {
        let claim = connection
            .request_name_with_flags(BUS_NAME, fdo::RequestNameFlags::DoNotQueue.into())
            .await;
        if secret_service_name_claimed(claim)? {
            return Ok(true);
        }
        if !announced {
            eprintln!(
                "FactorSeal: {BUS_NAME} is currently provided by another process; FactorSeal takes over when it is released"
            );
            announced = true;
        }
        loop {
            if should_stop()? {
                return Ok(false);
            }
            tokio::time::sleep(poll).await;
            let owned = bus
                .name_has_owner(name.clone())
                .await
                .map_err(|error| dbus_error(error.into()))?;
            if !owned {
                break;
            }
        }
    }
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

    #[test]
    fn an_owned_secret_service_name_is_a_nonfatal_integration_conflict() {
        assert!(!secret_service_name_claimed(Err::<(), _>(zbus::Error::NameTaken)).unwrap());
        assert!(secret_service_name_claimed(Ok(())).unwrap());
    }

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
            .authorize_secret_service_namespace(
                &caller,
                NAMESPACE,
                [
                    GrantPermission::Get,
                    GrantPermission::Put,
                    GrantPermission::Delete,
                ],
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
                &Zeroizing::new(b"first".to_vec()),
                "text/plain".to_owned(),
                false,
            )
            .unwrap();
        assert!(created);
        assert_eq!(
            agent
                .store
                .get(secret_item(&item.id))
                .unwrap()
                .unwrap()
                .as_slice(),
            b"first"
        );
        assert_eq!(agent.all_items().unwrap(), vec![item.clone()]);

        agent
            .set_secret(
                &item.id,
                &Zeroizing::new(b"second".to_vec()),
                "application/octet-stream".to_owned(),
            )
            .unwrap();
        assert_eq!(
            agent
                .store
                .get(secret_item(&item.id))
                .unwrap()
                .unwrap()
                .as_slice(),
            b"second"
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

    #[test]
    fn sessions_are_owner_bound_and_bounded() {
        let (_directory, agent) = agent();
        for index in 0..MAX_SESSIONS {
            let (session, _) =
                ProtocolSession::open(secret_service_protocol::ALGORITHM_PLAIN, &[]).unwrap();
            agent
                .open_session(
                    format!("{SESSION_PREFIX}{index}"),
                    "owner".to_owned(),
                    session,
                )
                .unwrap();
        }
        let (extra, _) =
            ProtocolSession::open(secret_service_protocol::ALGORITHM_PLAIN, &[]).unwrap();
        assert!(matches!(
            agent.open_session("extra".to_owned(), "owner".to_owned(), extra),
            Err(fdo::Error::LimitsExceeded(_))
        ));
        assert!(
            agent
                .close_session(&format!("{SESSION_PREFIX}0"), "other")
                .is_err()
        );
        agent
            .close_session(&format!("{SESSION_PREFIX}0"), "owner")
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn secret_service_name_is_taken_over_once_the_previous_owner_releases_it() {
        // Skips outside a desktop session and when a real Secret Service owns
        // the bus name; Linux CI runs the suite under `dbus-run-session`.
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let Ok(previous_owner) = Connection::session().await else {
                return;
            };
            match previous_owner
                .request_name_with_flags(BUS_NAME, zbus::fdo::RequestNameFlags::DoNotQueue.into())
                .await
            {
                Ok(_) => {}
                Err(zbus::Error::NameTaken) => return,
                Err(error) => panic!("could not register the Secret Service test name: {error}"),
            }
            let claimant = Connection::session().await.unwrap();
            let poll = Duration::from_millis(1);
            // Stopping while another provider still owns the name gives up.
            let claimed = claim_secret_service_name(&claimant, poll, || Ok(true))
                .await
                .unwrap();
            assert!(!claimed);
            // Release the name only once the claimant is observed waiting for it.
            let release = Arc::new(tokio::sync::Notify::new());
            let releaser = {
                let release = Arc::clone(&release);
                let previous_owner = previous_owner.clone();
                tokio::spawn(async move {
                    release.notified().await;
                    assert!(previous_owner.release_name(BUS_NAME).await.unwrap());
                })
            };
            let claimed = claim_secret_service_name(&claimant, poll, || {
                release.notify_one();
                Ok(false)
            })
            .await
            .unwrap();
            assert!(claimed);
            releaser.await.unwrap();
            let bus = fdo::DBusProxy::new(&claimant).await.unwrap();
            let owner = bus
                .get_name_owner(zbus::names::BusName::try_from(BUS_NAME).unwrap())
                .await
                .unwrap();
            assert_eq!(
                owner.to_string(),
                claimant.unique_name().unwrap().to_string()
            );
        });
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
            let server_connection = Connection::session()
                .await
                .expect("DBUS_SESSION_BUS_ADDRESS must identify a reachable session bus");
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
            let secret: Secret = item_proxy
                .call("GetSecret", &(session.clone(),))
                .await
                .unwrap();
            assert_eq!(secret.2, b"second");
            let _prompt: OwnedObjectPath = item_proxy.call("Delete", &()).await.unwrap();

            let session_proxy =
                Proxy::new(&client, BUS_NAME, session, "org.freedesktop.Secret.Session")
                    .await
                    .unwrap();
            session_proxy.call::<_, _, ()>("Close", &()).await.unwrap();
            assert!(session_proxy.call::<_, _, ()>("Close", &()).await.is_err());
        });
    }
}

//! Linux `org.freedesktop.secrets` adapter backed by the Factorseal vault.
//!
//! The adapter owns the well-known bus name for as long as its host process
//! runs and mirrors the vault's seal state onto the Secret Service `Locked`
//! properties, the way gnome-keyring keeps answering with locked collections
//! instead of disappearing. While sealed it has no database access at all:
//! reads and writes fail with `org.freedesktop.Secret.Error.IsLocked`,
//! `Unlock` hands back a prompt, and the prompt asks the host to unseal. Once
//! unsealed, every vault access goes through the vault protocol under the
//! host's own grant, so the adapter never holds keys of its own. The session
//! bus already authenticates peers as the current desktop user, which is the
//! same boundary provided by the other Secret Service implementations.
//!
//! Two hosts exist: the graphical Desktop, which serves the adapter for the
//! whole session and bridges to its vault worker over the native socket, and
//! the headless agent, which serves it in-process for as long as the vault
//! stays unsealed.

// zbus interface methods must own decoded D-Bus arguments, including headers
// and object paths; changing these signatures to references breaks dispatch.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use secret_service_protocol::{Session as ProtocolSession, SessionOutput};
use tokio::sync::{mpsc, oneshot};
use zbus::object_server::ObjectServer;
use zbus::zvariant::{OwnedObjectPath, OwnedValue};
use zbus::{Connection, fdo};
use zeroize::Zeroizing;

use super::{VaultClient, VaultError, VaultResult};

mod agent;
mod interfaces;

pub use agent::NAMESPACE;
use agent::{Agent, Store};
#[cfg(test)]
use agent::{INDEX_ITEM, Index};
use interfaces::{Collection, Item, Prompt, Service};

const BUS_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/factorseal";
const DEFAULT_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";
const ITEM_PREFIX: &str = "/org/freedesktop/secrets/collection/factorseal/";
const SESSION_PREFIX: &str = "/org/freedesktop/secrets/session/";
const PROMPT_PREFIX: &str = "/org/freedesktop/secrets/prompt/";
const MAX_SESSIONS: usize = 1024;
const TAKEOVER_POLL: Duration = Duration::from_secs(1);

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
type Properties = HashMap<String, OwnedValue>;

/// Permissions the adapter needs on its vault namespace.
#[cfg(feature = "vault-store")]
pub const SECRET_SERVICE_PERMISSIONS: [super::GrantPermission; 4] = [
    super::GrantPermission::Get,
    super::GrantPermission::Put,
    super::GrantPermission::Delete,
    super::GrantPermission::Seal,
];

/// Brings up the host's unlock interface when a client runs a prompt.
///
/// Called from the adapter's own thread; implementations must not block.
pub trait SecretServicePrompter: Send + Sync + 'static {
    fn request_unlock(&self);
}

/// Serves `org.freedesktop.secrets` for the lifetime of the value.
///
/// The name is claimed as soon as the session bus allows it and released on
/// drop. Between [`install`](Self::install) and [`uninstall`](Self::uninstall)
/// the collection is unlocked and backed by the vault; otherwise it reports
/// `Locked` and turns `Unlock` into prompts.
pub struct SecretServiceHost {
    shared: Arc<Shared>,
    commands: mpsc::UnboundedSender<Command>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl SecretServiceHost {
    /// Start serving on the session bus from a dedicated thread.
    pub fn start(prompter: Arc<dyn SecretServicePrompter>) -> VaultResult<Self> {
        Self::start_with(prompter, TAKEOVER_POLL)
    }

    fn start_with(prompter: Arc<dyn SecretServicePrompter>, poll: Duration) -> VaultResult<Self> {
        let (commands, receiver) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared::new(prompter));
        let frontend = Arc::clone(&shared);
        let thread = std::thread::Builder::new()
            .name("factorseal-secret-service".to_owned())
            .spawn(move || {
                if let Err(error) = run_frontend(&frontend, receiver, poll) {
                    eprintln!("FactorSeal: Secret Service stopped: {error}");
                }
            })
            .map_err(|error| {
                VaultError::Protocol(format!("could not start Secret Service thread: {error}"))
            })?;
        Ok(Self {
            shared,
            commands,
            thread: Some(thread),
        })
    }

    /// Back the collection with an unsealed vault reached through `client`.
    ///
    /// The host's executable must hold the adapter's namespace grant. Item
    /// objects appear once the index has loaded and pending prompts complete.
    /// Loading happens on the adapter thread; failures are reported there.
    pub fn install(&self, client: Box<dyn VaultClient>) -> VaultResult<()> {
        self.send(Command::Install {
            store: Store::remote(client),
            reply: None,
        })
    }

    #[cfg(any(feature = "vault", test))]
    fn install_store(&self, store: Store) -> VaultResult<oneshot::Receiver<VaultResult<()>>> {
        let (reply, done) = oneshot::channel();
        self.send(Command::Install {
            store,
            reply: Some(reply),
        })?;
        Ok(done)
    }

    /// Report the vault sealed: drop the index, lock the collection, and keep
    /// prompts pending for the next unseal.
    pub fn uninstall(&self) -> VaultResult<()> {
        self.send(Command::Uninstall)
    }

    /// Complete every pending prompt as dismissed, for a host whose unlock
    /// interface went away without unsealing.
    pub fn dismiss_prompts(&self) -> VaultResult<()> {
        self.send(Command::DismissPrompts)
    }

    /// Whether an unsealed vault currently backs the collection.
    #[must_use]
    pub fn is_installed(&self) -> bool {
        !self.shared.locked()
    }

    fn send(&self, command: Command) -> VaultResult<()> {
        self.commands.send(command).map_err(|_| stopped())
    }
}

impl Drop for SecretServiceHost {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Serve Secret Service in-process until `stopping` is set or the vault seals.
///
/// The internal Factorseal binary is granted this namespace and mediates the
/// session-bus API. This is intentionally separate from grants issued to IPC
/// clients of the vault protocol.
#[cfg(feature = "vault")]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn serve_secret_service(
    service: Arc<super::VaultService>,
    stopping: Arc<std::sync::atomic::AtomicBool>,
) -> VaultResult<()> {
    use std::sync::atomic::Ordering;

    let executable = std::env::current_exe().map_err(|error| {
        VaultError::Protocol(format!("could not resolve Factorseal executable: {error}"))
    })?;
    let caller = super::linux::linux_caller_identity_for_executable(executable)?;
    service.authorize_secret_service_namespace(
        &caller,
        NAMESPACE,
        SECRET_SERVICE_PERMISSIONS,
        unix_time(),
    )?;
    let host = SecretServiceHost::start(Arc::new(NoPrompter))?;
    host.install_store(Store::in_process(Arc::clone(&service), caller))?
        .blocking_recv()
        .map_err(|_| stopped())??;
    while !stopping.load(Ordering::Acquire) && !service.expire_if_needed(unix_time())? {
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(host);
    Ok(())
}

/// The headless agent has no unlock interface: it only serves while unsealed.
#[cfg(feature = "vault")]
struct NoPrompter;

#[cfg(feature = "vault")]
impl SecretServicePrompter for NoPrompter {
    fn request_unlock(&self) {}
}

enum Command {
    Install {
        store: Store,
        reply: Option<oneshot::Sender<VaultResult<()>>>,
    },
    Uninstall,
    DismissPrompts,
    Stop,
}

/// State shared between the interface objects and the host.
struct Shared {
    agent: RwLock<Option<Arc<Agent>>>,
    sessions: Mutex<HashMap<String, SessionState>>,
    prompts: Mutex<Vec<String>>,
    prompter: Arc<dyn SecretServicePrompter>,
}

impl Shared {
    fn new(prompter: Arc<dyn SecretServicePrompter>) -> Self {
        Self {
            agent: RwLock::new(None),
            sessions: Mutex::new(HashMap::new()),
            prompts: Mutex::new(Vec::new()),
            prompter,
        }
    }

    fn locked(&self) -> bool {
        self.agent.read().map_or(true, |agent| agent.is_none())
    }

    fn agent(&self) -> Result<Arc<Agent>, SecretServiceError> {
        self.agent.read().map_err(poisoned)?.clone().ok_or_else(|| {
            SecretServiceError::IsLocked("the FactorSeal vault is sealed".to_owned())
        })
    }

    fn set_agent(&self, agent: Option<Arc<Agent>>) -> Result<Option<Arc<Agent>>, fdo::Error> {
        let mut slot = self.agent.write().map_err(poisoned)?;
        Ok(std::mem::replace(&mut slot, agent))
    }

    fn register_prompt(&self, path: String) -> fdo::Result<()> {
        self.prompts.lock().map_err(poisoned)?.push(path);
        Ok(())
    }

    fn prompt_pending(&self, path: &str) -> fdo::Result<bool> {
        Ok(self
            .prompts
            .lock()
            .map_err(poisoned)?
            .iter()
            .any(|pending| pending == path))
    }

    fn take_prompt(&self, path: &str) -> fdo::Result<bool> {
        let mut prompts = self.prompts.lock().map_err(poisoned)?;
        let before = prompts.len();
        prompts.retain(|pending| pending != path);
        Ok(prompts.len() != before)
    }

    fn take_prompts(&self) -> fdo::Result<Vec<String>> {
        Ok(std::mem::take(&mut *self.prompts.lock().map_err(poisoned)?))
    }

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

/// Errors with Secret Service specific names, alongside the generic ones.
#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub(super) enum SecretServiceError {
    #[zbus(error)]
    ZBus(zbus::Error),
    /// The object is locked and cannot be read or written until unlocked.
    IsLocked(String),
}

impl From<fdo::Error> for SecretServiceError {
    fn from(error: fdo::Error) -> Self {
        Self::ZBus(zbus::Error::FDO(Box::new(error)))
    }
}

fn run_frontend(
    shared: &Arc<Shared>,
    mut commands: mpsc::UnboundedReceiver<Command>,
    poll: Duration,
) -> VaultResult<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            VaultError::Protocol(format!("could not start Secret Service runtime: {error}"))
        })?;
    runtime.block_on(async move {
        let connection = Connection::session().await.map_err(dbus_error)?;
        // Register every object before claiming the name, so a caller queued
        // on the name never reaches an empty service.
        let server = connection.object_server();
        server
            .at(
                SERVICE_PATH,
                Service {
                    shared: Arc::clone(shared),
                },
            )
            .await
            .map_err(dbus_error)?;
        for path in [COLLECTION_PATH, DEFAULT_ALIAS_PATH] {
            server
                .at(
                    path,
                    Collection {
                        shared: Arc::clone(shared),
                    },
                )
                .await
                .map_err(dbus_error)?;
        }
        if !claim_name(&connection, shared, &mut commands, poll).await? {
            return Ok(());
        }
        while let Some(command) = commands.recv().await {
            if matches!(command, Command::Stop) {
                break;
            }
            apply(shared, server, command).await;
        }
        complete_prompts(shared, server, true).await;
        uninstall(shared, server).await;
        let _ = connection.release_name(BUS_NAME).await;
        Ok(())
    })
}

/// Claim the Secret Service name, taking it over from a previous provider
/// once that provider releases it.
///
/// Another Secret Service (gnome-keyring, KWallet, or a second FactorSeal
/// instance) may own `org.freedesktop.secrets` when the host starts. Giving
/// up at that point left the name unowned for the rest of the session once
/// the other provider exited or crashed, while the desktop activation helper
/// kept waiting on this process to publish it. Commands keep being applied
/// while waiting. Returns `false` when the host stopped first.
async fn claim_name(
    connection: &Connection,
    shared: &Arc<Shared>,
    commands: &mut mpsc::UnboundedReceiver<Command>,
    poll: Duration,
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
            tokio::select! {
                command = commands.recv() => match command {
                    None | Some(Command::Stop) => return Ok(false),
                    Some(command) => apply(shared, connection.object_server(), command).await,
                },
                () = tokio::time::sleep(poll) => {
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
    }
}

async fn apply(shared: &Arc<Shared>, server: &ObjectServer, command: Command) {
    match command {
        Command::Install { store, reply } => {
            let result = install(shared, server, store).await;
            match reply {
                Some(reply) => {
                    let _ = reply.send(result);
                }
                None => {
                    if let Err(error) = result {
                        eprintln!(
                            "FactorSeal: Secret Service could not publish the vault: {error}"
                        );
                    }
                }
            }
        }
        Command::Uninstall => uninstall(shared, server).await,
        Command::DismissPrompts => complete_prompts(shared, server, true).await,
        Command::Stop => {}
    }
}

async fn install(shared: &Arc<Shared>, server: &ObjectServer, store: Store) -> VaultResult<()> {
    let agent = tokio::task::spawn_blocking(move || Agent::load(store))
        .await
        .map_err(|_| VaultError::Protocol("Secret Service index load panicked".to_owned()))??;
    let agent = Arc::new(agent);
    for id in agent.item_ids()? {
        let path = item_path(&id).map_err(|error| VaultError::Protocol(error.to_string()))?;
        server
            .at(
                path,
                Item {
                    shared: Arc::clone(shared),
                    id,
                },
            )
            .await
            .map_err(dbus_error)?;
    }
    shared
        .set_agent(Some(agent))
        .map_err(|error| VaultError::Protocol(error.to_string()))?;
    announce_lock_state(server).await;
    complete_prompts(shared, server, false).await;
    Ok(())
}

async fn uninstall(shared: &Arc<Shared>, server: &ObjectServer) {
    let Ok(previous) = shared.set_agent(None) else {
        return;
    };
    let Some(agent) = previous else {
        return;
    };
    for id in agent.item_ids().unwrap_or_default() {
        if let Ok(path) = item_path(&id) {
            let _ = server.remove::<Item, _>(path).await;
        }
    }
    announce_lock_state(server).await;
}

/// Tell clients that `Locked` flipped, the way gnome-keyring announces
/// collection lock changes.
async fn announce_lock_state(server: &ObjectServer) {
    for path in [COLLECTION_PATH, DEFAULT_ALIAS_PATH] {
        if let Ok(collection) = server.interface::<_, Collection>(path).await {
            let _ = collection
                .get()
                .await
                .locked_changed(collection.signal_emitter())
                .await;
        }
    }
    if let (Ok(service), Ok(path)) = (
        server.interface::<_, Service>(SERVICE_PATH).await,
        object_path(COLLECTION_PATH),
    ) {
        let _ = Service::collection_changed(service.signal_emitter(), path).await;
    }
}

async fn complete_prompts(shared: &Arc<Shared>, server: &ObjectServer, dismissed: bool) {
    let Ok(paths) = shared.take_prompts() else {
        return;
    };
    for path in paths {
        if let Ok(prompt) = server.interface::<_, Prompt>(path.as_str()).await
            && let Ok(result) = prompt_result(dismissed)
        {
            let _ = Prompt::completed(prompt.signal_emitter(), dismissed, result).await;
        }
        let _ = server.remove::<Prompt, _>(path.as_str()).await;
    }
}

/// `Unlock` prompts complete with the unlocked object paths, or with an
/// empty string when dismissed, matching the reference implementations.
fn prompt_result(dismissed: bool) -> fdo::Result<OwnedValue> {
    if dismissed {
        OwnedValue::try_from(zbus::zvariant::Value::from(String::new())).map_err(failed)
    } else {
        OwnedValue::try_from(zbus::zvariant::Value::from(vec![object_path(
            COLLECTION_PATH,
        )?]))
        .map_err(failed)
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

fn stopped() -> VaultError {
    VaultError::Protocol("Secret Service host is not running".to_owned())
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
    use std::pin::Pin;

    use super::*;
    use crate::vault::VaultStore;
    use crate::{CallerIdentity, CallerPlatform, UnsealLeasePolicy, Vault, VaultService};
    use zbus::Proxy;
    use zbus::export::futures_core::Stream;

    #[test]
    fn an_owned_secret_service_name_is_a_nonfatal_integration_conflict() {
        assert!(!secret_service_name_claimed(Err::<(), _>(zbus::Error::NameTaken)).unwrap());
        assert!(secret_service_name_claimed(Ok(())).unwrap());
    }

    fn test_service() -> (tempfile::TempDir, Arc<VaultService>, CallerIdentity) {
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
            .authorize_secret_service_namespace(&caller, NAMESPACE, SECRET_SERVICE_PERMISSIONS, 100)
            .unwrap();
        (directory, service, caller)
    }

    fn agent() -> (tempfile::TempDir, Agent) {
        let (directory, service, caller) = test_service();
        let agent = Agent::load(Store::in_process(service, caller)).unwrap();
        (directory, agent)
    }

    /// Records unlock requests so a test can wait for the host's callback.
    struct ChannelPrompter(mpsc::UnboundedSender<()>);

    impl SecretServicePrompter for ChannelPrompter {
        fn request_unlock(&self) {
            let _ = self.0.send(());
        }
    }

    async fn next<S: Stream + Unpin>(stream: &mut S) -> Option<S::Item> {
        std::future::poll_fn(|context| Pin::new(&mut *stream).poll_next(context)).await
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Developers outside a desktop session, or with another Secret Service
    /// already registered, can still run the unit suite. Linux CI runs it
    /// under `dbus-run-session`, where these exchanges are mandatory on an
    /// isolated bus. Returns a connection that briefly held the name.
    async fn free_session_bus() -> Option<Connection> {
        std::env::var_os("DBUS_SESSION_BUS_ADDRESS")?;
        let connection = Connection::session().await.ok()?;
        match connection
            .request_name_with_flags(BUS_NAME, fdo::RequestNameFlags::DoNotQueue.into())
            .await
        {
            Ok(_) => Some(connection),
            Err(zbus::Error::NameTaken) => None,
            Err(error) => panic!("could not register the Secret Service test name: {error}"),
        }
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
    fn lock_seals_the_vault_through_the_adapter_grant() {
        let (_directory, service, caller) = test_service();
        let store = Store::in_process(Arc::clone(&service), caller);
        store.seal().unwrap();
        assert!(store.get("anything").is_err());
        assert!(service.expire_if_needed(200).unwrap());
    }

    #[test]
    fn sessions_are_owner_bound_and_bounded() {
        let (sender, _receiver) = mpsc::unbounded_channel();
        let shared = Shared::new(Arc::new(ChannelPrompter(sender)));
        for index in 0..MAX_SESSIONS {
            let (session, _) =
                ProtocolSession::open(secret_service_protocol::ALGORITHM_PLAIN, &[]).unwrap();
            shared
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
            shared.open_session("extra".to_owned(), "owner".to_owned(), extra),
            Err(fdo::Error::LimitsExceeded(_))
        ));
        assert!(
            shared
                .close_session(&format!("{SESSION_PREFIX}0"), "other")
                .is_err()
        );
        shared
            .close_session(&format!("{SESSION_PREFIX}0"), "owner")
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn session_bus_crud_uses_the_exported_secret_service_interfaces() {
        runtime().block_on(async {
            let Some(server_connection) = free_session_bus().await else {
                return;
            };
            let (_directory, agent) = agent();
            let (sender, _receiver) = mpsc::unbounded_channel();
            let shared = Arc::new(Shared::new(Arc::new(ChannelPrompter(sender))));
            shared.set_agent(Some(Arc::new(agent))).unwrap();
            let server = server_connection.object_server();
            server
                .at(
                    SERVICE_PATH,
                    Service {
                        shared: Arc::clone(&shared),
                    },
                )
                .await
                .unwrap();
            server
                .at(COLLECTION_PATH, Collection { shared })
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
            assert!(!collection.get_property::<bool>("Locked").await.unwrap());
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

    async fn unlock_prompt(client: &Connection, service: &Proxy<'_>) -> Proxy<'static> {
        let (unlocked, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = service
            .call("Unlock", &(vec![object_path(COLLECTION_PATH).unwrap()],))
            .await
            .unwrap();
        assert!(unlocked.is_empty());
        assert!(prompt.as_str().starts_with(PROMPT_PREFIX));
        Proxy::new(client, BUS_NAME, prompt, "org.freedesktop.Secret.Prompt")
            .await
            .unwrap()
    }

    async fn completion(
        prompt: &Proxy<'_>,
        signals: &mut zbus::proxy::SignalStream<'_>,
    ) -> (bool, OwnedValue) {
        let _ = prompt;
        let signal = next(signals).await.expect("prompt completes");
        signal.body().deserialize().unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_sealed_host_locks_the_collection_and_completes_prompts_on_unseal() {
        runtime().block_on(async {
            let Some(probe) = free_session_bus().await else {
                return;
            };
            assert!(probe.release_name(BUS_NAME).await.unwrap());
            let client = Connection::session().await.unwrap();
            let bus = fdo::DBusProxy::new(&client).await.unwrap();
            let mut owners = bus
                .receive_name_owner_changed_with_args(&[(0, BUS_NAME)])
                .await
                .unwrap();
            let (prompted_sender, mut prompted) = mpsc::unbounded_channel();
            let host = SecretServiceHost::start_with(
                Arc::new(ChannelPrompter(prompted_sender)),
                Duration::from_millis(1),
            )
            .unwrap();
            let owned = next(&mut owners).await.unwrap();
            assert!(owned.args().unwrap().new_owner().is_some());
            assert!(!host.is_installed());

            let service = Proxy::new(
                &client,
                BUS_NAME,
                SERVICE_PATH,
                "org.freedesktop.Secret.Service",
            )
            .await
            .unwrap();
            let collection = Proxy::new(
                &client,
                BUS_NAME,
                COLLECTION_PATH,
                "org.freedesktop.Secret.Collection",
            )
            .await
            .unwrap();
            assert!(collection.get_property::<bool>("Locked").await.unwrap());
            assert!(
                collection
                    .get_property::<Vec<OwnedObjectPath>>("Items")
                    .await
                    .unwrap()
                    .is_empty()
            );
            let alias: OwnedObjectPath = service
                .call("ReadAlias", &("default",))
                .await
                .unwrap();
            assert_eq!(alias.as_str(), DEFAULT_ALIAS_PATH);
            let input = OwnedValue::try_from(zbus::zvariant::Value::from(String::new())).unwrap();
            let (_output, session): (OwnedValue, OwnedObjectPath) = service
                .call("OpenSession", &("plain".to_owned(), input))
                .await
                .unwrap();
            let error = service
                .call::<_, _, HashMap<OwnedObjectPath, Secret>>(
                    "GetSecrets",
                    &(Vec::<OwnedObjectPath>::new(), session.clone()),
                )
                .await
                .unwrap_err();
            assert!(
                matches!(&error, zbus::Error::MethodError(name, ..) if name.as_str() == "org.freedesktop.Secret.Error.IsLocked"),
                "sealed reads must report IsLocked, got {error:?}"
            );

            // A prompt asks the host to unseal and completes once the vault is
            // published.
            let prompt = unlock_prompt(&client, &service).await;
            let mut completed = prompt.receive_signal("Completed").await.unwrap();
            prompt.call::<_, _, ()>("Prompt", &("",)).await.unwrap();
            prompted.recv().await.expect("host asked to unlock");
            let (_directory, vault_service, caller) = test_service();
            host.install_store(Store::in_process(vault_service, caller))
                .unwrap()
                .await
                .unwrap()
                .unwrap();
            let (dismissed, result) = completion(&prompt, &mut completed).await;
            assert!(!dismissed);
            assert_eq!(
                Vec::<OwnedObjectPath>::try_from(result).unwrap(),
                vec![object_path(COLLECTION_PATH).unwrap()]
            );
            assert!(host.is_installed());
            assert!(!collection.get_property::<bool>("Locked").await.unwrap());
            assert!(prompt.call::<_, _, ()>("Prompt", &("",)).await.is_err());

            // Sealing again relocks the collection and announces it.
            let mut locked_changes = collection.receive_property_changed::<bool>("Locked").await;
            host.uninstall().unwrap();
            loop {
                let change = next(&mut locked_changes).await.unwrap();
                if change.get().await.unwrap() {
                    break;
                }
            }
            assert!(!host.is_installed());

            // Clients can dismiss their own prompt.
            let prompt = unlock_prompt(&client, &service).await;
            let mut completed = prompt.receive_signal("Completed").await.unwrap();
            prompt.call::<_, _, ()>("Dismiss", &()).await.unwrap();
            let (dismissed, _) = completion(&prompt, &mut completed).await;
            assert!(dismissed);

            // The host dismisses every pending prompt when its unlock
            // interface goes away.
            let prompt = unlock_prompt(&client, &service).await;
            let mut completed = prompt.receive_signal("Completed").await.unwrap();
            host.dismiss_prompts().unwrap();
            let (dismissed, _) = completion(&prompt, &mut completed).await;
            assert!(dismissed);

            drop(host);
            let released = next(&mut owners).await.unwrap();
            assert!(released.args().unwrap().new_owner().is_none());
        });
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_host_takes_over_the_name_once_the_previous_owner_releases_it() {
        runtime().block_on(async {
            let Some(previous_owner) = free_session_bus().await else {
                return;
            };
            let observer = Connection::session().await.unwrap();
            let bus = fdo::DBusProxy::new(&observer).await.unwrap();
            let mut owners = bus
                .receive_name_owner_changed_with_args(&[(0, BUS_NAME)])
                .await
                .unwrap();
            let (sender, _receiver) = mpsc::unbounded_channel();
            let host = SecretServiceHost::start_with(
                Arc::new(ChannelPrompter(sender)),
                Duration::from_millis(1),
            )
            .unwrap();
            assert!(previous_owner.release_name(BUS_NAME).await.unwrap());
            let taken_over = loop {
                let change = next(&mut owners).await.unwrap();
                let args = change.args().unwrap();
                if let Some(owner) = args.new_owner().as_ref() {
                    break owner.to_string();
                }
            };
            assert_ne!(
                taken_over,
                previous_owner.unique_name().unwrap().to_string()
            );
            drop(host);
        });
    }
}

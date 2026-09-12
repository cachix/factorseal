//! Linux `org.freedesktop.secrets` adapter backed by the Factorseal vault.
//!
//! The adapter owns the well-known bus name for as long as its host process
//! runs and mirrors the vault's seal state onto the Secret Service `Locked`
//! properties, the way gnome-keyring keeps answering with locked collections
//! instead of disappearing. While sealed it has no database access at all:
//! secret reads and writes fail with `org.freedesktop.Secret.Error.IsLocked`,
//! `Unlock` hands back a prompt, and the prompt asks the host to unseal. Once
//! unsealed, secret operations go through a privileged host bridge, which
//! checks project and operation grants for the authenticated D-Bus executable.
//! The adapter never holds keys of its own. New grants require signed approval
//! and can expire or be revoked through the permission registry.
//! Item metadata stays in the encrypted vault. Searches while sealed
//! ask the host to unlock, then resume against the decrypted index.
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
use interfaces::{Collection, Item, Prompt, Service, Session};

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

/// Brings up the host's unlock interface for a prompt or a sealed search.
///
/// Called from the adapter's own thread; implementations must not block.
pub trait SecretServicePrompter: Send + Sync + 'static {
    fn request_unlock(&self);

    fn finish_access(&self, _context: SecretServiceAccessContext) {}

    fn supports_input(&self) -> bool {
        false
    }

    fn request_input(&self, _request: SecretServiceInputRequest) {}

    /// Review a sealed lookup in the host's UI. Dropping the request denies it.
    /// Hosts without a review UI retain the ordinary unlock behavior.
    fn request_access(&self, mut request: SecretServiceAccessRequest) {
        request.allow();
        self.request_unlock();
    }
}

/// Information supplied with a credential lookup. Attributes are caller-provided;
/// the bus authenticates the sender, and process paths are best-effort OS data.
#[derive(Clone, Debug, Default)]
pub struct SecretServiceAccessContext {
    pub attributes: std::collections::BTreeMap<String, String>,
    pub sender: String,
    pub process_id: Option<u32>,
    pub executable: Option<std::path::PathBuf>,
    pub working_directory: Option<std::path::PathBuf>,
}

/// A pending lookup requiring a decision before it can resume after unlocking.
pub struct SecretServiceAccessRequest {
    pub context: SecretServiceAccessContext,
    decision: Option<oneshot::Sender<AccessDecision>>,
}

/// One user-confirmed write. No durable write grant is created.
pub struct SecretServiceInputRequest {
    pub context: SecretServiceAccessContext,
    pub initial: Option<super::WireSecret>,
    decision: Option<oneshot::Sender<Option<super::WireSecret>>>,
}

impl SecretServiceInputRequest {
    pub fn save(&mut self, value: super::WireSecret) {
        if let Some(sender) = self.decision.take() {
            let _ = sender.send(Some(value));
        }
    }
    pub fn deny(&mut self) {
        if let Some(sender) = self.decision.take() {
            let _ = sender.send(None);
        }
    }
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.decision
            .as_ref()
            .is_some_and(oneshot::Sender::is_closed)
    }
}

enum AccessDecision {
    Allow,
    Deny,
}

impl SecretServiceAccessRequest {
    /// Allow this pending lookup. This does not create a persistent vault grant.
    pub fn allow(&mut self) {
        if let Some(decision) = self.decision.take() {
            let _ = decision.send(AccessDecision::Allow);
        }
    }

    /// Deny explicitly; dropping the request means its dialog was dismissed.
    pub fn deny(&mut self) {
        if let Some(decision) = self.decision.take() {
            let _ = decision.send(AccessDecision::Deny);
        }
    }

    /// Whether the client stopped waiting before deciding.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.decision
            .as_ref()
            .is_some_and(oneshot::Sender::is_closed)
    }

    #[must_use]
    pub fn is_pending(&self) -> bool {
        self.decision
            .as_ref()
            .is_some_and(|decision| !decision.is_closed())
    }
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

    /// Complete pending prompts as dismissed, for a host whose unlock
    /// interface went away without unsealing. Uninvoked prompts retain the
    /// result until the client calls `Prompt`.
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
    prompts: Mutex<HashMap<String, PromptState>>,
    prompter: Arc<dyn SecretServicePrompter>,
    searches: Mutex<Vec<oneshot::Sender<bool>>>,
}

enum PromptState {
    Waiting,
    Invoked,
    Completed { dismissed: bool },
}

impl Shared {
    fn new(prompter: Arc<dyn SecretServicePrompter>) -> Self {
        Self {
            agent: RwLock::new(None),
            sessions: Mutex::new(HashMap::new()),
            prompts: Mutex::new(HashMap::new()),
            prompter,
            searches: Mutex::new(Vec::new()),
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

    /// Keep each lookup behind its own decision, even if another request
    /// unlocks the vault while this one is still being reviewed.
    async fn unlock_for_search(
        &self,
        context: SecretServiceAccessContext,
    ) -> Result<(), SecretServiceError> {
        self.unlock_for_search_with_timeout(context, Duration::from_mins(2))
            .await
    }

    async fn unlock_for_search_with_timeout(
        &self,
        context: SecretServiceAccessContext,
        timeout: Duration,
    ) -> Result<(), SecretServiceError> {
        let receiver = {
            let mut searches = self.searches.lock().map_err(poisoned)?;
            if !self.locked() {
                return Ok(());
            }
            searches.retain(|search| !search.is_closed());
            let (sender, receiver) = oneshot::channel();
            searches.push(sender);
            receiver
        };
        let (decision, approval) = oneshot::channel();
        self.prompter.request_access(SecretServiceAccessRequest {
            context,
            decision: Some(decision),
        });
        let wait = async {
            match approval.await {
                Ok(AccessDecision::Allow) => {}
                Ok(AccessDecision::Deny) => {
                    return Err(SecretServiceError::AccessDenied(
                        "FactorSeal access request was denied".to_owned(),
                    ));
                }
                Err(_) => {
                    return Err(SecretServiceError::Cancelled(
                        "FactorSeal access dialog was dismissed".to_owned(),
                    ));
                }
            }
            if !self.locked() {
                return Ok(());
            }
            match receiver.await {
                Ok(false) => self.agent().map(|_| ()),
                Ok(true) => Err(SecretServiceError::Cancelled(
                    "FactorSeal unlock was cancelled".to_owned(),
                )),
                Err(_) => Err(failed("FactorSeal stopped while waiting for unlock").into()),
            }
        };
        match tokio::time::timeout(timeout, wait).await {
            Ok(result) => result,
            Err(_) => Err(SecretServiceError::TimedOut(format!(
                "FactorSeal access request timed out after {} seconds",
                timeout.as_secs()
            ))),
        }
    }

    async fn input_secret(
        &self,
        context: SecretServiceAccessContext,
        initial: super::WireSecret,
    ) -> Result<super::WireSecret, SecretServiceError> {
        if std::str::from_utf8(initial.expose()).is_err() {
            return Err(failed("Secure entry supports text secrets only").into());
        }
        let (decision, receiver) = oneshot::channel();
        self.prompter.request_input(SecretServiceInputRequest {
            context,
            initial: Some(initial),
            decision: Some(decision),
        });
        match tokio::time::timeout(Duration::from_mins(2), receiver).await {
            Ok(Ok(Some(value))) => Ok(value),
            Ok(Ok(None)) => Err(SecretServiceError::AccessDenied(
                "FactorSeal secret write was denied".to_owned(),
            )),
            Ok(Err(_)) => Err(SecretServiceError::Cancelled(
                "FactorSeal secret entry dialog was dismissed".to_owned(),
            )),
            Err(_) => Err(SecretServiceError::TimedOut(
                "FactorSeal secret entry timed out after 120 seconds".to_owned(),
            )),
        }
    }

    async fn authorized_agent(
        &self,
        sender: &str,
        service: &str,
        operation: super::PermissionOperation,
    ) -> Result<Arc<Agent>, SecretServiceError> {
        let agent = self.agent()?;
        let mut pending = None;
        let deadline = tokio::time::Instant::now() + Duration::from_mins(2);
        loop {
            let response = tokio::task::spawn_blocking({
                let store = agent.store.clone();
                let sender = sender.to_owned();
                let service = service.to_owned();
                let pending = pending.clone();
                move || store.check_access(sender, service, operation, pending)
            })
            .await
            .map_err(failed)?
            .map_err(failed)?;
            response.check_delivery().map_err(failed)?;
            match response.result {
                Ok(super::VaultResponseBody::PermissionWait {
                    status: super::PermissionWaitStatus::Granted,
                }) => {
                    if pending.take().is_some() {
                        continue;
                    }
                    return Ok(Arc::new(Agent {
                        store: agent.store.delegated(
                            sender.to_owned(),
                            service.to_owned(),
                            operation,
                        ),
                    }));
                }
                Ok(super::VaultResponseBody::PermissionWait {
                    status: super::PermissionWaitStatus::Pending,
                }) => {}
                Ok(super::VaultResponseBody::PermissionWait {
                    status: super::PermissionWaitStatus::Expired,
                }) => {
                    return Err(SecretServiceError::TimedOut(
                        "FactorSeal permission request expired".to_owned(),
                    ));
                }
                Err(error) if error.interaction.is_some() => {
                    pending = error.interaction.map(|reference| reference.id);
                }
                Ok(super::VaultResponseBody::PermissionWait {
                    status: super::PermissionWaitStatus::Denied,
                }) => {
                    return Err(SecretServiceError::AccessDenied(
                        "FactorSeal keyring access was denied".to_owned(),
                    ));
                }
                Err(error) => return Err(failed(error.message).into()),
                Ok(_) => return Err(failed("Unexpected FactorSeal permission response").into()),
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(SecretServiceError::TimedOut(
                    "FactorSeal permission request timed out after 120 seconds".to_owned(),
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    fn complete_searches(&self, dismissed: bool) {
        if let Ok(mut searches) = self.searches.lock() {
            for search in searches.drain(..) {
                let _ = search.send(dismissed);
            }
        }
    }

    fn set_agent(&self, agent: Option<Arc<Agent>>) -> Result<Option<Arc<Agent>>, fdo::Error> {
        let mut slot = self.agent.write().map_err(poisoned)?;
        Ok(std::mem::replace(&mut slot, agent))
    }

    fn register_prompt(&self, path: String) -> fdo::Result<()> {
        self.prompts
            .lock()
            .map_err(poisoned)?
            .insert(path, PromptState::Waiting);
        Ok(())
    }

    // Invocation and host completion share a lock so exactly one emits Completed.
    fn invoke_prompt(&self, path: &str) -> fdo::Result<Option<bool>> {
        let mut prompts = self.prompts.lock().map_err(poisoned)?;
        let state = prompts.get_mut(path).ok_or_else(|| {
            fdo::Error::Failed("Secret Service prompt already completed".to_owned())
        })?;
        let dismissed = match state {
            PromptState::Completed { dismissed } => Some(*dismissed),
            _ if !self.locked() => Some(false),
            _ => None,
        };
        if dismissed.is_some() {
            prompts.remove(path);
        } else {
            *state = PromptState::Invoked;
        }
        Ok(dismissed)
    }

    fn take_prompt(&self, path: &str) -> fdo::Result<bool> {
        Ok(self
            .prompts
            .lock()
            .map_err(poisoned)?
            .remove(path)
            .is_some())
    }

    fn take_prompts(&self, dismissed: bool) -> fdo::Result<Vec<String>> {
        let mut prompts = self.prompts.lock().map_err(poisoned)?;
        let mut ready = Vec::new();
        prompts.retain(|path, state| {
            if matches!(state, PromptState::Invoked) {
                ready.push(path.clone());
                false
            } else {
                if matches!(state, PromptState::Waiting) {
                    *state = PromptState::Completed { dismissed };
                }
                true
            }
        });
        Ok(ready)
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

    fn discard_client_sessions(&self, owner: &str) -> fdo::Result<Vec<String>> {
        let mut sessions = self.sessions.lock().map_err(poisoned)?;
        let mut paths = Vec::new();
        sessions.retain(|path, session| {
            if session.owner == owner {
                paths.push(path.clone());
                false
            } else {
                true
            }
        });
        Ok(paths)
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
        value: &[u8],
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
    AccessDenied(String),
    Cancelled(String),
    TimedOut(String),
    /// The host has no way to satisfy the request, such as an entry dialog
    /// on a host without a user interface.
    NotSupported(String),
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
        let bus = fdo::DBusProxy::new(&connection).await.map_err(dbus_error)?;
        // Subscribe before publishing the service, including clients which
        // disconnect while their OpenSession reply is being prepared.
        let mut changes = bus.receive_name_owner_changed().await.map_err(dbus_error)?;
        let cleanup_shared = Arc::clone(shared);
        let cleanup_connection = connection.clone();
        let cleanup = tokio::spawn(async move {
            use zbus::export::futures_core::Stream;
            while let Some(change) =
                std::future::poll_fn(|cx| std::pin::Pin::new(&mut changes).poll_next(cx)).await
            {
                let Ok(args) = change.args() else {
                    continue;
                };
                if args.new_owner().is_some() || !args.name().as_str().starts_with(':') {
                    continue;
                }
                if let Ok(paths) = cleanup_shared.discard_client_sessions(args.name().as_str()) {
                    for path in paths {
                        let _ = cleanup_connection
                            .object_server()
                            .remove::<Session, _>(path)
                            .await;
                    }
                }
            }
        });
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
        cleanup.abort();
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
    shared.complete_searches(dismissed);
    let Ok(paths) = shared.take_prompts(dismissed) else {
        return;
    };
    for path in paths {
        if let Ok(prompt) = server.interface::<_, Prompt>(path.as_str()).await
            && let Ok(result) = prompt.get().await.result(dismissed)
        {
            let _ = Prompt::completed(prompt.signal_emitter(), dismissed, result).await;
        }
        let _ = server.remove::<Prompt, _>(path.as_str()).await;
    }
}

/// `Unlock` prompts complete with the unlocked object paths, or with an
/// empty string when dismissed, matching the reference implementations.
fn prompt_result(dismissed: bool, objects: Vec<OwnedObjectPath>) -> fdo::Result<OwnedValue> {
    if dismissed {
        OwnedValue::try_from(zbus::zvariant::Value::from(String::new())).map_err(failed)
    } else {
        OwnedValue::try_from(zbus::zvariant::Value::from(objects)).map_err(failed)
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

    #[test]
    fn completion_waits_for_invocation_and_is_consumed_once() {
        for dismissed in [false, true] {
            let (sender, _) = mpsc::unbounded_channel();
            let shared = Shared::new(Arc::new(ChannelPrompter(sender)));
            shared.register_prompt("early".to_owned()).unwrap();
            shared.register_prompt("late".to_owned()).unwrap();
            assert_eq!(shared.invoke_prompt("early").unwrap(), None);
            assert_eq!(shared.take_prompts(dismissed).unwrap(), vec!["early"]);
            assert_eq!(shared.invoke_prompt("late").unwrap(), Some(dismissed));
            assert!(shared.invoke_prompt("early").is_err());
            assert!(shared.invoke_prompt("late").is_err());
            assert!(shared.take_prompts(dismissed).unwrap().is_empty());
        }
    }

    fn test_service_unprivileged() -> (tempfile::TempDir, Arc<VaultService>, CallerIdentity) {
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

    fn test_service() -> (tempfile::TempDir, Arc<VaultService>, CallerIdentity) {
        let result = test_service_unprivileged();
        let mut executables = vec![std::env::current_exe().unwrap()];
        if let Some(path) = std::env::var_os("FACTORSEAL_TEST_SECRET_TOOL") {
            executables.push(path.into());
        }
        for executable in executables {
            let peer =
                crate::vault::linux::linux_caller_identity_for_executable(executable).unwrap();
            result
                .1
                .authorize_document_kind(
                    &peer,
                    crate::DocumentKind::LinuxSecretService,
                    [
                        super::super::GrantPermission::Get,
                        super::super::GrantPermission::Put,
                        super::super::GrantPermission::Delete,
                    ],
                    None,
                    100,
                )
                .unwrap();
        }
        result
    }

    #[test]
    fn access_timeout_is_distinct_from_denial_and_dismissal() {
        runtime().block_on(async {
            let (sender, mut requests) = mpsc::unbounded_channel();
            let shared = Arc::new(Shared::new(Arc::new(ReviewPrompter(sender))));
            let task = tokio::spawn({
                let shared = shared.clone();
                async move {
                    shared
                        .unlock_for_search_with_timeout(
                            SecretServiceAccessContext::default(),
                            Duration::from_millis(20),
                        )
                        .await
                }
            });
            let _request = requests.recv().await.unwrap();
            assert!(matches!(
                task.await.unwrap(),
                Err(SecretServiceError::TimedOut(_))
            ));
        });
    }

    #[test]
    fn keyring_project_grants_bind_peer_operation_and_revocation() {
        use crate::vault::{
            PermissionOperation, PermissionState, PermissionWaitStatus, VaultAction, VaultRequest,
            VaultResponseBody,
        };
        runtime().block_on(async {
            let bus = zbus::Connection::session().await.unwrap();
            let sender = bus.unique_name().unwrap().to_string();
            let (directory, service, manager) = test_service_unprivileged();
            service.authorize_permission_manager(&manager, 100).unwrap();
            let call = |action| service.handle(&manager, VaultRequest::new(action).unwrap(), 101);
            let access = |project: &str, operation| VaultAction::KeyringAccess {
                sender: sender.clone(),
                service: format!("service/secretspec/{project}/dev/TOKEN"),
                operation,
                action: None,
                pending: None,
            };
            let denied = call(access("first", PermissionOperation::Get));
            let id = denied.result.unwrap_err().interaction.unwrap().id;
            let VaultResponseBody::Permissions { permissions, .. } =
                call(VaultAction::ListPermissions).result.unwrap()
            else {
                panic!("permissions")
            };
            let permission = permissions.iter().find(|p| p.id == id).unwrap();
            let peer = crate::vault::linux::linux_caller_identity_for_executable(
                std::env::current_exe().unwrap(),
            )
            .unwrap();
            assert_eq!(permission.principal.application_id, peer.application_id());
            assert_eq!(
                permission.principal.executable_digest,
                *peer.executable_digest()
            );
            let PermissionState::Pending { challenge, .. } = &permission.state else {
                panic!("pending")
            };
            let signature = Vault::unseal_for_test(&directory.path().join("factorseal"))
                .unwrap()
                .sign_permission_challenge(&id, challenge, Some(3600))
                .unwrap();
            call(VaultAction::ApprovePermission {
                id: id.clone(),
                signature,
                duration_seconds: Some(3600),
            })
            .result
            .unwrap();
            assert!(matches!(
                call(access("first", PermissionOperation::Get)).result,
                Ok(VaultResponseBody::PermissionWait {
                    status: PermissionWaitStatus::Granted
                })
            ));
            assert!(
                call(access("first", PermissionOperation::Put))
                    .result
                    .unwrap_err()
                    .interaction
                    .is_some()
            );
            assert!(
                call(access("second", PermissionOperation::Get))
                    .result
                    .unwrap_err()
                    .interaction
                    .is_some()
            );
            assert!(
                service
                    .handle(
                        &peer,
                        VaultRequest::new(access("first", PermissionOperation::Get)).unwrap(),
                        101
                    )
                    .result
                    .is_err(),
                "a project grant must not grant bridge authority"
            );
            call(VaultAction::RevokePermission { id }).result.unwrap();
            assert!(
                call(access("first", PermissionOperation::Get))
                    .result
                    .unwrap_err()
                    .interaction
                    .is_some()
            );
        });
    }

    struct EditingPrompter;
    impl SecretServicePrompter for EditingPrompter {
        fn request_unlock(&self) {}
        fn supports_input(&self) -> bool {
            true
        }
        fn request_input(&self, mut request: SecretServiceInputRequest) {
            assert_eq!(request.initial.as_ref().unwrap().expose(), b"supplied");
            request.save(super::super::WireSecret::new(b"edited".to_vec()).unwrap());
        }
    }

    #[test]
    fn secure_keyring_write_saves_edited_value_without_a_write_grant() {
        runtime().block_on(async {
            let server = free_session_bus().await.unwrap();
            let (_directory, vault, manager) = test_service_unprivileged();
            vault.authorize_permission_manager(&manager, 100).unwrap();
            let agent =
                Arc::new(Agent::load(Store::in_process(vault.clone(), manager.clone())).unwrap());
            let shared = Arc::new(Shared::new(Arc::new(EditingPrompter)));
            shared.set_agent(Some(agent.clone())).unwrap();
            server
                .object_server()
                .at(
                    SERVICE_PATH,
                    Service {
                        shared: shared.clone(),
                    },
                )
                .await
                .unwrap();
            server
                .object_server()
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
            let (_, session): (OwnedValue, OwnedObjectPath) = service
                .call("OpenSession", &("plain", input))
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
            let properties = HashMap::from([
                (
                    "org.freedesktop.Secret.Item.Label".to_owned(),
                    OwnedValue::try_from(zbus::zvariant::Value::from("Test")).unwrap(),
                ),
                (
                    "org.freedesktop.Secret.Item.Attributes".to_owned(),
                    OwnedValue::try_from(zbus::zvariant::Value::from(HashMap::from([(
                        "service".to_owned(),
                        "secretspec/write-test/default/TOKEN".to_owned(),
                    )])))
                    .unwrap(),
                ),
            ]);
            let (path, _): (OwnedObjectPath, OwnedObjectPath) = collection
                .call(
                    "CreateItem",
                    &(
                        properties,
                        (
                            session,
                            Vec::<u8>::new(),
                            b"supplied".to_vec(),
                            "text/plain",
                        ),
                        false,
                    ),
                )
                .await
                .unwrap();
            let id = item_id(&path).unwrap();
            assert_eq!(
                &*agent.store.get(secret_item(id)).unwrap().unwrap(),
                b"edited"
            );
            let response = vault.handle(
                &manager,
                super::super::VaultRequest::new(super::super::VaultAction::ListPermissions)
                    .unwrap(),
                unix_time(),
            );
            let super::super::VaultResponseBody::Permissions { permissions, .. } =
                response.result.unwrap()
            else {
                panic!("permissions")
            };
            assert!(
                permissions.is_empty(),
                "saving must not create a persistent write permission"
            );
        });
    }

    #[cfg(feature = "key-protection")]
    #[test]
    fn a_host_without_an_entry_dialog_refuses_input_at_once() {
        runtime().block_on(async {
            let Some(server) = free_session_bus().await else {
                return;
            };
            let (_directory, vault, manager) = test_service_unprivileged();
            let shared = Arc::new(Shared::new(Arc::new(NoPrompter)));
            shared
                .set_agent(Some(Arc::new(
                    Agent::load(Store::in_process(vault, manager)).unwrap(),
                )))
                .unwrap();
            server
                .object_server()
                .at(SERVICE_PATH, Service { shared })
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
            let (_local, remote) = std::os::unix::net::UnixStream::pair().unwrap();
            let fd = zbus::zvariant::OwnedFd::from(std::os::fd::OwnedFd::from(remote));
            // The CLI agent has no dialog; the provider relies on this answer
            // arriving immediately so it can write through an approval.
            let refused = service
                .call::<_, _, ()>("InputForIpc", &(HashMap::from([("project", "test")]), fd))
                .await
                .unwrap_err();
            assert!(
                matches!(&refused, zbus::Error::MethodError(name, ..) if name.as_str().ends_with(".NotSupported")),
                "{refused:?}"
            );
        });
    }

    #[cfg(feature = "key-protection")]
    #[test]
    fn native_secure_input_exchanges_values_only_over_the_private_channel() {
        runtime().block_on(async {
            let server = free_session_bus().await.unwrap();
            let (_directory, vault, manager) = test_service_unprivileged();
            let peer = crate::vault::linux::linux_caller_identity_for_executable(
                std::env::current_exe().unwrap(),
            )
            .unwrap();
            let shared = Arc::new(Shared::new(Arc::new(EditingPrompter)));
            shared
                .set_agent(Some(Arc::new(
                    Agent::load(Store::in_process(vault.clone(), manager)).unwrap(),
                )))
                .unwrap();
            server
                .object_server()
                .at(SERVICE_PATH, Service { shared })
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
            let (_local, remote) = std::os::unix::net::UnixStream::pair().unwrap();
            let fd = zbus::zvariant::OwnedFd::from(std::os::fd::OwnedFd::from(remote));
            let denied = service.call::<_, _, ()>("InputForIpc", &(HashMap::from([("project", "test")]), fd)).await.unwrap_err();
            assert!(matches!(denied, zbus::Error::MethodError(name, ..) if name.as_str().ends_with(".AccessDenied")));
            vault.authorize_permission_manager(&peer, unix_time()).unwrap();
            let (mut local, remote) = std::os::unix::net::UnixStream::pair().unwrap();
            let exchange = tokio::task::spawn_blocking(move || {
                local
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                crate::desktop_worker::send(
                    &mut local,
                    &super::super::WireSecret::new(b"supplied".to_vec()).unwrap(),
                )
                .unwrap();
                crate::desktop_worker::receive::<super::super::WireSecret>(&mut local).unwrap()
            });
            let fd = zbus::zvariant::OwnedFd::from(std::os::fd::OwnedFd::from(remote));
            service
                .call::<_, _, ()>("InputForIpc", &(HashMap::from([("project", "test")]), fd))
                .await
                .unwrap();
            assert_eq!(exchange.await.unwrap().expose(), b"edited");
        });
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
        assert!(agent.store.get(secret_item(&item.id)).unwrap().is_none());
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

    #[test]
    fn item_unlock_results_preserve_requested_paths() {
        let (_directory, agent) = agent();
        let (item, _) = agent
            .create_or_replace(
                "Example".to_owned(),
                HashMap::new(),
                &Zeroizing::new(b"value".to_vec()),
                "text/plain".to_owned(),
                false,
            )
            .unwrap();
        let (sender, _) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared::new(Arc::new(ChannelPrompter(sender))));
        let item_path = item_path(&item.id).unwrap();
        let alias = object_path(DEFAULT_ALIAS_PATH).unwrap();
        let missing = object_path(&format!("{ITEM_PREFIX}missing")).unwrap();
        shared.set_agent(Some(Arc::new(agent))).unwrap();
        let prompt = Prompt {
            shared,
            path: "unused".to_owned(),
            objects: vec![item_path.clone(), alias.clone(), missing],
        };
        assert_eq!(
            Vec::<OwnedObjectPath>::try_from(prompt.result(false).unwrap()).unwrap(),
            vec![item_path, alias],
        );
    }

    #[test]
    fn sealed_search_requests_unlock_and_resumes() {
        runtime().block_on(async {
            if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
                return;
            }
            let connection = Connection::session().await.unwrap();
            let (sender, mut requested) = mpsc::unbounded_channel();
            let shared = Arc::new(Shared::new(Arc::new(ChannelPrompter(sender))));
            let service = Service {
                shared: Arc::clone(&shared),
            };
            let collection = Collection {
                shared: Arc::clone(&shared),
            };
            let message = zbus::Message::method_call(SERVICE_PATH, "SearchItems")
                .unwrap()
                .sender(connection.unique_name().unwrap())
                .unwrap()
                .build(&())
                .unwrap();
            let searches = async {
                tokio::join!(
                    service.search_items(
                        HashMap::new(),
                        message.header(),
                        &connection,
                        connection.object_server()
                    ),
                    collection.search_items(
                        HashMap::new(),
                        message.header(),
                        &connection,
                        connection.object_server()
                    ),
                )
            };
            let unlock = async {
                requested.recv().await.unwrap();
                requested.recv().await.unwrap();
                let (_directory, vault, caller) = test_service();
                install(
                    &shared,
                    connection.object_server(),
                    Store::in_process(vault, caller),
                )
                .await
                .unwrap();
            };
            let ((service_result, collection_result), ()) = tokio::join!(searches, unlock);
            assert!(service_result.unwrap().0.is_empty());
            assert!(collection_result.unwrap().is_empty());
            assert!(requested.try_recv().is_err());
        });
    }

    #[test]
    fn sealed_search_dismissal_allows_another_request() {
        runtime().block_on(async {
            let (sender, mut requested) = mpsc::unbounded_channel();
            let shared = Shared::new(Arc::new(ChannelPrompter(sender)));
            for _ in 0..2 {
                let (result, ()) = tokio::join!(
                    shared.unlock_for_search(SecretServiceAccessContext::default()),
                    async {
                        requested.recv().await.unwrap();
                        shared.complete_searches(true);
                    }
                );
                assert!(matches!(result, Err(SecretServiceError::Cancelled(_))));
            }
        });
    }

    struct ReviewPrompter(mpsc::UnboundedSender<SecretServiceAccessRequest>);

    impl SecretServicePrompter for ReviewPrompter {
        fn request_unlock(&self) {}
        fn request_access(&self, request: SecretServiceAccessRequest) {
            let _ = self.0.send(request);
        }
    }

    #[test]
    fn another_unlock_does_not_bypass_pending_access_review() {
        runtime().block_on(async {
            let (sender, mut requests) = mpsc::unbounded_channel();
            let shared = Arc::new(Shared::new(Arc::new(ReviewPrompter(sender))));
            let lookup = tokio::spawn({
                let shared = Arc::clone(&shared);
                async move {
                    shared
                        .unlock_for_search(SecretServiceAccessContext::default())
                        .await
                }
            });
            let mut request = requests.recv().await.unwrap();
            let (_directory, service, caller) = test_service();
            shared
                .set_agent(Some(Arc::new(
                    Agent::load(Store::in_process(service, caller)).unwrap(),
                )))
                .unwrap();
            shared.complete_searches(false);
            tokio::task::yield_now().await;
            assert!(
                !lookup.is_finished(),
                "unlock alone must not approve a reviewed request"
            );
            request.allow();
            assert!(lookup.await.unwrap().is_ok());
        });
    }

    #[test]
    fn denying_one_access_request_does_not_approve_or_cancel_another() {
        runtime().block_on(async {
            let (sender, mut requests) = mpsc::unbounded_channel();
            let shared = Arc::new(Shared::new(Arc::new(ReviewPrompter(sender))));
            let start = || {
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    shared
                        .unlock_for_search(SecretServiceAccessContext::default())
                        .await
                })
            };
            let first = start();
            let mut denied = requests.recv().await.unwrap();
            let second = start();
            let mut allowed = requests.recv().await.unwrap();
            denied.deny();
            assert!(matches!(
                first.await.unwrap(),
                Err(SecretServiceError::AccessDenied(_))
            ));
            assert!(!second.is_finished());
            let (_directory, service, caller) = test_service();
            shared
                .set_agent(Some(Arc::new(
                    Agent::load(Store::in_process(service, caller)).unwrap(),
                )))
                .unwrap();
            shared.complete_searches(false);
            allowed.allow();
            assert!(second.await.unwrap().is_ok());
        });
    }

    async fn wait_for_no_sessions(host: &SecretServiceHost) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if host.shared.sessions.lock().unwrap().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("disconnected clients must release sessions");
    }

    /// Run with FACTORSEAL_TEST_SECRET_TOOL pointing to libsecret's secret-tool
    /// on an isolated bus. This exercises a real client's lookup state machine.
    #[cfg(target_os = "linux")]
    #[test]
    #[allow(clippy::too_many_lines)]
    fn libsecret_store_seal_lookup() {
        let Some(tool) = std::env::var_os("FACTORSEAL_TEST_SECRET_TOOL") else {
            return;
        };
        runtime().block_on(async {
            let probe = free_session_bus()
                .await
                .expect("test needs an isolated, unused bus");
            let client = Connection::session().await.unwrap();
            let bus = fdo::DBusProxy::new(&client).await.unwrap();
            let mut owners = bus
                .receive_name_owner_changed_with_args(&[(0, BUS_NAME)])
                .await
                .unwrap();
            let (directory, service, caller) = test_service();
            let (sender, mut requested) = mpsc::unbounded_channel();
            let host = SecretServiceHost::start_with(
                Arc::new(ChannelPrompter(sender)),
                Duration::from_millis(1),
            )
            .unwrap();
            probe.release_name(BUS_NAME).await.unwrap();
            loop {
                if next(&mut owners)
                    .await
                    .unwrap()
                    .args()
                    .unwrap()
                    .new_owner()
                    .is_some()
                {
                    break;
                }
            }
            host.install_store(Store::in_process(Arc::clone(&service), caller.clone()))
                .unwrap()
                .await
                .unwrap()
                .unwrap();
            let stored = tokio::task::spawn_blocking({
                let tool = tool.clone();
                move || {
                    use std::io::Write as _;
                    use std::process::{Command, Stdio};
                    let mut child = Command::new(tool)
                        .args([
                            "store",
                            "--label=Regression",
                            "service",
                            "factorseal-regression",
                        ])
                        .stdin(Stdio::piped())
                        .stdout(Stdio::piped())
                        .stderr(Stdio::piped())
                        .spawn()
                        .unwrap();
                    child
                        .stdin
                        .take()
                        .unwrap()
                        .write_all(b"regression-secret")
                        .unwrap();
                    child.wait_with_output().unwrap()
                }
            })
            .await
            .unwrap();
            assert!(
                stored.status.success(),
                "{}",
                String::from_utf8_lossy(&stored.stderr)
            );
            let collection = Proxy::new(
                &client,
                BUS_NAME,
                COLLECTION_PATH,
                "org.freedesktop.Secret.Collection",
            )
            .await
            .unwrap();
            let mut changes = collection.receive_property_changed::<bool>("Locked").await;
            service.seal().unwrap();
            host.uninstall().unwrap();
            loop {
                if next(&mut changes).await.unwrap().get().await.unwrap() {
                    break;
                }
            }
            drop(service);
            // Restart sealed: neither search metadata nor secret values are
            // available until Desktop completes the requested unlock.
            drop(host);
            while next(&mut owners)
                .await
                .unwrap()
                .args()
                .unwrap()
                .new_owner()
                .is_some()
            {}
            let (sender, mut requested_after_restart) = mpsc::unbounded_channel();
            let host = SecretServiceHost::start_with(
                Arc::new(ChannelPrompter(sender)),
                Duration::from_millis(1),
            )
            .unwrap();
            while next(&mut owners)
                .await
                .unwrap()
                .args()
                .unwrap()
                .new_owner()
                .is_none()
            {}
            assert!(!host.is_installed());
            let sealed_lookup = tokio::task::spawn_blocking({
                let tool = tool.clone();
                move || {
                    std::process::Command::new(tool)
                        .args(["lookup", "service", "factorseal-regression"])
                        .output()
                        .unwrap()
                }
            });
            tokio::time::timeout(Duration::from_secs(5), requested_after_restart.recv())
                .await
                .unwrap()
                .expect("lookup must request Desktop unlock");
            assert!(!sealed_lookup.is_finished());
            assert!(requested.try_recv().is_err());
            assert!(
                !directory
                    .path()
                    .join("factorseal/secret-service-metadata.json")
                    .exists()
            );
            // Complete the requested unlock; the pending lookup must resume.
            let root = directory.path().join("factorseal");
            let store = VaultStore::open(&root, Vault::unseal_for_test(&root).unwrap()).unwrap();
            let service =
                Arc::new(VaultService::new(store, 100, UnsealLeasePolicy::default()).unwrap());
            service
                .authorize_secret_service_namespace(
                    &caller,
                    NAMESPACE,
                    SECRET_SERVICE_PERMISSIONS,
                    100,
                )
                .unwrap();
            host.install_store(Store::in_process(service, caller))
                .unwrap()
                .await
                .unwrap()
                .unwrap();
            let result = tokio::time::timeout(Duration::from_secs(10), sealed_lookup)
                .await
                .unwrap()
                .unwrap();
            assert!(
                result.status.success(),
                "{}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert_eq!(result.stdout, b"regression-secret");
            wait_for_no_sessions(&host).await;
            // More short-lived connections than the global limit must remain
            // usable without asking clients to explicitly Close on shutdown.
            for _ in 0..=MAX_SESSIONS {
                let transient = Connection::session().await.unwrap();
                let proxy = Proxy::new(
                    &transient,
                    BUS_NAME,
                    SERVICE_PATH,
                    "org.freedesktop.Secret.Service",
                )
                .await
                .unwrap();
                let input =
                    OwnedValue::try_from(zbus::zvariant::Value::from(String::new())).unwrap();
                let (_, path): (OwnedValue, OwnedObjectPath) =
                    proxy.call("OpenSession", &("plain", input)).await.unwrap();
                drop(proxy);
                transient.close().await.unwrap();
                wait_for_no_sessions(&host).await;
                let stale = Proxy::new(&client, BUS_NAME, path, "org.freedesktop.Secret.Session")
                    .await
                    .unwrap();
                assert!(stale.call::<_, _, ()>("Close", &()).await.is_err());
            }
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
            // This client invokes Prompt only after Desktop finishes unlocking.
            let (_directory, vault_service, caller) = test_service();
            let agent = Agent::load(Store::in_process(Arc::clone(&vault_service), caller.clone())).unwrap();
            let (item, _) = agent.create_or_replace(
                "Example".to_owned(), HashMap::new(), &Zeroizing::new(b"value".to_vec()),
                "text/plain".to_owned(), false,
            ).unwrap();
            let requested = vec![item_path(&item.id).unwrap(), object_path(DEFAULT_ALIAS_PATH).unwrap()];
            let (_, path): (Vec<OwnedObjectPath>, OwnedObjectPath) = service.call("Unlock", &(requested.clone(),)).await.unwrap();
            let late_prompt = Proxy::new(&client, BUS_NAME, path, "org.freedesktop.Secret.Prompt").await.unwrap();
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
            let mut late_completed = late_prompt.receive_signal("Completed").await.unwrap();
            late_prompt.call::<_, _, ()>("Prompt", &("",)).await.unwrap();
            let (dismissed, result) = completion(&late_prompt, &mut late_completed).await;
            assert!(!dismissed);
            assert_eq!(Vec::<OwnedObjectPath>::try_from(result).unwrap(), requested);
            assert!(prompted.try_recv().is_err());
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
            prompt.call::<_, _, ()>("Prompt", &("",)).await.unwrap();
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
    #[test]
    fn create_without_replace_allows_duplicate_attributes() {
        let (_directory, agent) = agent();
        for label in ["one", "two"] {
            agent
                .create_or_replace(
                    label.into(),
                    HashMap::new(),
                    &Zeroizing::new(b"value".to_vec()),
                    "text/plain".into(),
                    false,
                )
                .unwrap();
        }
        assert_eq!(agent.all_items().unwrap().len(), 2);
    }

    struct ArchiveAgent {
        agent: Arc<Agent>,
        service: Arc<crate::vault::VaultService>,
        caller: crate::vault::CallerIdentity,
    }

    impl std::ops::Deref for ArchiveAgent {
        type Target = Agent;
        fn deref(&self) -> &Agent {
            &self.agent
        }
    }

    fn archive_agent() -> (tempfile::TempDir, ArchiveAgent) {
        let (directory, service, caller) = test_service();
        // Exercise the same serialized request path used by the desktop backend.
        let backend = Store::in_process(Arc::clone(&service), caller.clone());
        let agent = Arc::new(Agent::load(Store::remote(Box::new(backend))).unwrap());
        (
            directory,
            ArchiveAgent {
                agent,
                service,
                caller,
            },
        )
    }
    impl crate::VaultClient for Store {
        fn request(&self, request: &crate::VaultRequest) -> VaultResult<crate::VaultResponse> {
            let decoded = crate::VaultRequest::decode(&request.encode()?)?;
            let response = self.backend_request(decoded)?;
            crate::VaultResponse::decode(&response.encode()?)
        }
    }

    fn import_item(
        target: &ArchiveAgent,
        entry: &crate::VaultArchiveEntry,
        replace_existing: bool,
    ) -> crate::VaultEntryImportStatus {
        use crate::{VaultAction, VaultRequest, VaultResponseBody, WireSecret};
        let response = target.service.handle(
            &target.caller,
            VaultRequest::new(VaultAction::ImportVaultEntry {
                entry: entry.metadata.clone(),
                value: WireSecret::new(entry.value.expose().to_vec()).unwrap(),
                evict_at: entry.evict_at,
                replace_existing,
            })
            .unwrap(),
            unix_time(),
        );
        let VaultResponseBody::VaultEntryImported { status } = response.result.unwrap() else {
            panic!("unexpected import response")
        };
        status
    }

    fn exported_item(source: &ArchiveAgent) -> crate::VaultArchiveEntry {
        source
            .service
            .authorize_permission_manager(&source.caller, unix_time())
            .unwrap();
        let entries = crate::read_vault_export(&source.store, |_| true).unwrap();
        assert_eq!(
            entries.len(),
            1,
            "the singleton index is not a portable item"
        );
        let encrypted = crate::encrypt_vault_archive(
            &crate::VaultArchive::new(unix_time(), entries),
            b"opal nebula lantern saffron velocity",
        )
        .unwrap();
        crate::decrypt_vault_archive(&encrypted, b"opal nebula lantern saffron velocity")
            .unwrap()
            .entries
            .pop()
            .unwrap()
    }

    #[test]
    fn keyring_restore_merges_live_metadata_and_values_and_survives_next_write() {
        use crate::VaultEntryImportStatus::{Added, KeptExisting, Replaced};
        let (_source_dir, source) = archive_agent();
        let (saved, _) = source
            .create_or_replace(
                "Restored".into(),
                HashMap::new(),
                &Zeroizing::new(b"backup".to_vec()),
                "text/plain".into(),
                false,
            )
            .unwrap();
        let entry = exported_item(&source);
        let (_target_dir, target) = archive_agent();
        target
            .service
            .authorize_permission_manager(&target.caller, unix_time())
            .unwrap();
        let (unrelated, _) = target
            .create_or_replace(
                "Unrelated".into(),
                HashMap::new(),
                &Zeroizing::new(b"unrelated".to_vec()),
                "text/plain".into(),
                false,
            )
            .unwrap();
        assert_eq!(import_item(&target, &entry, false), Added);
        assert_eq!(target.item(&saved.id).unwrap().label, "Restored");
        target
            .set_secret(
                &saved.id,
                &Zeroizing::new(b"changed".to_vec()),
                "application/test".into(),
            )
            .unwrap();
        assert_eq!(import_item(&target, &entry, false), KeptExisting);
        assert_eq!(
            &*target.store.get(secret_item(&saved.id)).unwrap().unwrap(),
            b"changed"
        );
        assert_eq!(
            target.item(&saved.id).unwrap().content_type,
            "application/test"
        );
        assert_eq!(import_item(&target, &entry, true), Replaced);
        assert_eq!(
            &*target.store.get(secret_item(&saved.id)).unwrap().unwrap(),
            b"backup"
        );
        assert_eq!(target.item(&saved.id).unwrap().content_type, "text/plain");
        target
            .set_secret(
                &unrelated.id,
                &Zeroizing::new(b"next write".to_vec()),
                "text/plain".into(),
            )
            .unwrap();
        let reloaded = Agent::load(target.store.clone()).unwrap();
        assert_eq!(reloaded.all_items().unwrap().len(), 2);
        assert_eq!(reloaded.item(&saved.id).unwrap().label, "Restored");
        assert_eq!(
            &*reloaded
                .store
                .get(secret_item(&unrelated.id))
                .unwrap()
                .unwrap(),
            b"next write"
        );
    }

    #[test]
    fn malformed_keyring_import_does_not_change_index_or_values() {
        use crate::{VaultAction, VaultRequest, WireSecret};
        let (_source_dir, source) = archive_agent();
        source
            .create_or_replace(
                "Source".into(),
                HashMap::new(),
                &Zeroizing::new(b"secret".to_vec()),
                "text/plain".into(),
                false,
            )
            .unwrap();
        let entry = exported_item(&source);
        let (_target_dir, target) = archive_agent();
        target
            .service
            .authorize_permission_manager(&target.caller, unix_time())
            .unwrap();
        let response = target.service.handle(
            &target.caller,
            VaultRequest::new(VaultAction::ImportVaultEntry {
                entry: entry.metadata.clone(),
                value: WireSecret::new(b"malformed".to_vec()).unwrap(),
                evict_at: None,
                replace_existing: true,
            })
            .unwrap(),
            unix_time(),
        );
        assert!(response.result.is_err());
        assert!(target.all_items().unwrap().is_empty());
        assert!(
            target
                .store
                .get(entry.metadata.address.as_local().unwrap().0)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn imported_keyring_items_are_discoverable_and_readable_on_dbus() {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (_source_dir, source) = archive_agent();
            source
                .create_or_replace(
                    "Restored".into(),
                    HashMap::new(),
                    &Zeroizing::new(b"backup".to_vec()),
                    "text/plain".into(),
                    false,
                )
                .unwrap();
            let entry = exported_item(&source);
            let (_target_dir, target) = archive_agent();
            let target = Arc::new(target);
            target
                .service
                .authorize_permission_manager(&target.caller, unix_time())
                .unwrap();
            let server = Connection::session().await.unwrap();
            let (sender, _) = mpsc::unbounded_channel();
            let shared = Arc::new(Shared::new(Arc::new(ChannelPrompter(sender))));
            shared.set_agent(Some(Arc::clone(&target.agent))).unwrap();
            server
                .object_server()
                .at(
                    SERVICE_PATH,
                    Service {
                        shared: Arc::clone(&shared),
                    },
                )
                .await
                .unwrap();
            let client = Connection::session().await.unwrap();
            let proxy = Proxy::new(
                &client,
                server.unique_name().unwrap().to_owned(),
                SERVICE_PATH,
                "org.freedesktop.Secret.Service",
            )
            .await
            .unwrap();
            // The adapter and its D-Bus service existed before the import.
            import_item(&target, &entry, false);
            let (paths, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = proxy
                .call("SearchItems", &(HashMap::<String, String>::new(),))
                .await
                .unwrap();
            assert_eq!(paths.len(), 1);
            assert!(locked.is_empty());
            let input = OwnedValue::try_from(zbus::zvariant::Value::from(String::new())).unwrap();
            let (_, session): (OwnedValue, OwnedObjectPath) =
                proxy.call("OpenSession", &("plain", input)).await.unwrap();
            let item = Proxy::new(
                &client,
                server.unique_name().unwrap().to_owned(),
                paths[0].clone(),
                "org.freedesktop.Secret.Item",
            )
            .await
            .unwrap();
            let secret: Secret = item.call("GetSecret", &(session,)).await.unwrap();
            assert_eq!(secret.2, b"backup");
        });
    }
    #[test]
    fn concurrent_keyring_import_and_create_preserve_both_items() {
        let (_source_dir, source) = archive_agent();
        source
            .create_or_replace(
                "Imported".into(),
                HashMap::new(),
                &Zeroizing::new(b"backup".to_vec()),
                "text/plain".into(),
                false,
            )
            .unwrap();
        let entry = exported_item(&source);
        let (_target_dir, target) = archive_agent();
        target
            .service
            .authorize_permission_manager(&target.caller, unix_time())
            .unwrap();
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                import_item(&target, &entry, false);
            });
            barrier.wait();
            target
                .create_or_replace(
                    "Created".into(),
                    HashMap::new(),
                    &Zeroizing::new(b"new".to_vec()),
                    "text/plain".into(),
                    false,
                )
                .unwrap();
        });
        let items = target.all_items().unwrap();
        assert_eq!(items.len(), 2);
        for item in items {
            let expected = if item.label == "Imported" {
                b"backup".as_slice()
            } else {
                b"new".as_slice()
            };
            assert_eq!(
                &*target.store.get(secret_item(&item.id)).unwrap().unwrap(),
                expected
            );
        }
    }
    #[test]
    fn pre_fix_v1_backup_restores_into_empty_and_populated_keyrings() {
        let archive = crate::decrypt_vault_archive(
            include_bytes!("../../tests/fixtures/keyring-v1.factorseal"),
            b"synthetic archive orchard violet lantern 2026",
        )
        .unwrap();
        assert_eq!(archive.entries.len(), 1);
        for populated in [false, true] {
            let (_dir, target) = archive_agent();
            target
                .service
                .authorize_permission_manager(&target.caller, unix_time())
                .unwrap();
            if populated {
                target
                    .create_or_replace(
                        "Unrelated".into(),
                        HashMap::new(),
                        &Zeroizing::new(b"unrelated".to_vec()),
                        "text/plain".into(),
                        false,
                    )
                    .unwrap();
            }
            let entry = &archive.entries[0];
            assert_eq!(
                import_item(&target, entry, false),
                crate::VaultEntryImportStatus::Added
            );
            assert_eq!(
                import_item(&target, entry, false),
                crate::VaultEntryImportStatus::KeptExisting
            );
            assert_eq!(
                import_item(&target, entry, true),
                crate::VaultEntryImportStatus::Replaced
            );
            target
                .create_or_replace(
                    "Next write".into(),
                    HashMap::new(),
                    &Zeroizing::new(b"new".to_vec()),
                    "text/plain".into(),
                    false,
                )
                .unwrap();
            let reloaded = Agent::load(target.store.clone()).unwrap();
            let restored = reloaded.item("0123456789abcdef0123456789abcdef").unwrap();
            assert_eq!(restored.label, "Legacy fixture");
            assert_eq!(
                restored.attributes.get("service").unwrap(),
                "factorseal-release-drill"
            );
            assert_eq!(
                &*reloaded
                    .store
                    .get(secret_item(&restored.id))
                    .unwrap()
                    .unwrap(),
                b"synthetic legacy secret"
            );
            assert_eq!(
                reloaded.all_items().unwrap().len(),
                if populated { 3 } else { 2 }
            );
        }
    }
}

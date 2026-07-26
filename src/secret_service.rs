//! Linux Secret Service provider backed by an unlocked FactorSeal vault.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use dbus::arg::{PropMap, RefArg, Variant, prop_cast};
use dbus::blocking::SyncConnection;
use dbus::channel::{MatchingReceiver, Sender};
use dbus::strings::{Interface, Member};
use dbus::{Message, Path};
use dbus_crossroads::{Context, Crossroads, IfaceToken, MethodErr, PropContext};
use hkdf::Hkdf;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{Error as VaultError, UnlockedVault};

const BUS_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const COLLECTION_PATH: &str = "/org/freedesktop/secrets/collection/factorseal";
const DEFAULT_ALIAS_PATH: &str = "/org/freedesktop/secrets/aliases/default";
const SESSION_PREFIX: &str = "/org/freedesktop/secrets/session/s";
const PROMPT_PREFIX: &str = "/org/freedesktop/secrets/prompt/p";
const ITEM_PREFIX: &str = "/org/freedesktop/secrets/collection/factorseal/";
const ROOT_PATH: &str = "/";
const COLLECTION_RESOURCE: &str = "*";
const INDEX_FORMAT: &str = "factorseal-secret-service-metadata";
const INDEX_VERSION: u32 = 1;
const ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";
const COLLECTION_LABEL: &str = "org.freedesktop.Secret.Collection.Label";
const ALGORITHM_PLAIN: &str = "plain";
const ALGORITHM_DH: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";
const AES_KEY_BYTES: usize = 16;
const AES_BLOCK_BYTES: usize = 16;
const DH_BYTES: usize = 128;
const DH_PRIME_BYTES: [u8; DH_BYTES] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

type Secret = (Path<'static>, Vec<u8>, Vec<u8>, String);
type DynVariant = Variant<Box<dyn RefArg + 'static>>;

/// Runtime settings for the Linux Secret Service provider.
#[derive(Clone, Debug)]
pub struct SecretServiceOptions {
    /// How long an approved application may reuse an item-specific grant.
    pub approval_ttl: Duration,
}

impl Default for SecretServiceOptions {
    fn default() -> Self {
        Self {
            approval_ttl: Duration::from_secs(15 * 60),
        }
    }
}

/// Errors returned while starting or running the Linux Secret Service provider.
#[derive(Debug, thiserror::Error)]
pub enum SecretServiceError {
    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error("D-Bus error: {0}")]
    Dbus(#[from] dbus::Error),

    #[error("another process already owns org.freedesktop.secrets")]
    NameAlreadyOwned,

    #[error("Secret Service state lock was poisoned")]
    Poisoned,

    #[error("Secret Service index is malformed: {0}")]
    InvalidIndex(String),
}

/// Serve the standard Linux Secret Service API until the process is stopped.
///
/// The caller must unlock the vault before starting the provider. Secret
/// Service sessions and grants are still scoped to each application's unique
/// D-Bus connection.
pub fn serve_secret_service(
    vault: UnlockedVault,
    options: SecretServiceOptions,
) -> Result<(), SecretServiceError> {
    use dbus::blocking::stdintf::org_freedesktop_dbus::RequestNameReply;

    let connection = Arc::new(SyncConnection::new_session()?);
    let reply = connection.request_name(BUS_NAME, false, false, true)?;
    if !matches!(
        reply,
        RequestNameReply::PrimaryOwner | RequestNameReply::AlreadyOwner
    ) {
        return Err(SecretServiceError::NameAlreadyOwned);
    }

    let (approval_sender, approval_receiver) = mpsc::channel();
    let agent = Arc::new(Agent::new(vault, options, approval_sender)?);
    let mut crossroads = Crossroads::new();
    let interfaces = register_interfaces(&mut crossroads);

    crossroads.insert(
        SERVICE_PATH,
        &[interfaces.service],
        ServiceObject(Arc::clone(&agent)),
    );
    crossroads.insert(
        COLLECTION_PATH,
        &[interfaces.collection],
        CollectionObject(Arc::clone(&agent)),
    );
    crossroads.insert(
        DEFAULT_ALIAS_PATH,
        &[interfaces.collection],
        CollectionObject(Arc::clone(&agent)),
    );
    for id in agent.item_ids()? {
        crossroads.insert(
            item_path(&id),
            &[interfaces.item],
            ItemObject {
                agent: Arc::clone(&agent),
                id,
            },
        );
    }

    let crossroads = Arc::new(Mutex::new(crossroads));
    let disconnect_agent = Arc::clone(&agent);
    connection.add_match(
        dbus::message::MatchRule::new_signal("org.freedesktop.DBus", "NameOwnerChanged"),
        move |(name, old_owner, new_owner): (String, String, String), _, _| {
            if name.starts_with(':') && !old_owner.is_empty() && new_owner.is_empty() {
                disconnect_agent.disconnect_owner(&name);
            }
            true
        },
    )?;
    let handler = Arc::clone(&crossroads);
    connection.start_receive(
        dbus::message::MatchRule::new_method_call(),
        Box::new(move |message, connection| {
            if let Ok(mut crossroads) = handler.lock() {
                let _ = crossroads.handle_message(message, connection);
            }
            true
        }),
    );

    loop {
        connection.process(Duration::from_millis(100))?;
        while let Ok(event) = approval_receiver.try_recv() {
            let completion = match agent.complete_prompt(event) {
                Ok(Some(completion)) => completion,
                Ok(None) => continue,
                Err(error) => {
                    eprintln!(
                        "factorseal: approval action for prompt {} failed: {error}",
                        event.prompt_id
                    );
                    PromptCompletion::dismissed(event.prompt_id)
                }
            };
            if let Some(item) = &completion.created {
                lock(&crossroads)?.insert(
                    item_path(&item.id),
                    &[interfaces.item],
                    ItemObject {
                        agent: Arc::clone(&agent),
                        id: item.id.clone(),
                    },
                );
                connection
                    .send(collection_signal("ItemCreated", item_path(&item.id)))
                    .map_err(|()| dbus::Error::new_failed("failed to send ItemCreated"))?;
            }
            if let Some(id) = &completion.deleted {
                let _ = lock(&crossroads)?.remove::<ItemObject>(&item_path(id));
                connection
                    .send(collection_signal("ItemDeleted", item_path(id)))
                    .map_err(|()| dbus::Error::new_failed("failed to send ItemDeleted"))?;
            }
            connection
                .send(completion.message())
                .map_err(|()| dbus::Error::new_failed("failed to send prompt completion"))?;
        }
    }
}

#[derive(Clone)]
struct ServiceObject(Arc<Agent>);

#[derive(Clone)]
struct CollectionObject(Arc<Agent>);

struct ItemObject {
    agent: Arc<Agent>,
    id: String,
}

struct SessionObject {
    agent: Arc<Agent>,
    owner: String,
}

struct PromptObject {
    agent: Arc<Agent>,
    id: u64,
    owner: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Index {
    format: String,
    version: u32,
    items: Vec<IndexItem>,
}

impl Default for Index {
    fn default() -> Self {
        Self {
            format: INDEX_FORMAT.to_owned(),
            version: INDEX_VERSION,
            items: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct IndexItem {
    id: String,
    service: String,
    account: String,
    label: String,
    attributes: HashMap<String, String>,
    content_type: String,
    item_type: String,
    created: u64,
    modified: u64,
}

struct Agent {
    vault: Arc<UnlockedVault>,
    index: Mutex<Index>,
    sessions: Mutex<HashMap<String, Session>>,
    grants: Mutex<HashMap<(String, String), Instant>>,
    prompts: Mutex<HashMap<u64, PendingPrompt>>,
    identities: Mutex<HashMap<String, CallerIdentity>>,
    next_id: AtomicU64,
    options: SecretServiceOptions,
    approval_sender: mpsc::Sender<ApprovalEvent>,
    approval_gate: Mutex<()>,
}

#[derive(Clone)]
struct Session {
    owner: String,
    cipher: SessionCipher,
}

#[derive(Clone)]
enum SessionCipher {
    Plain,
    Dh(Zeroizing<[u8; AES_KEY_BYTES]>),
}

#[derive(Clone, Debug)]
struct CallerIdentity {
    bus_name: String,
    process_id: Option<u32>,
    executable: Option<PathBuf>,
    grant_subject: String,
}

struct PendingPrompt {
    owner: String,
    action: PromptAction,
    started: bool,
}

enum PromptAction {
    Unlock {
        objects: Vec<PromptObjectRef>,
    },
    Create {
        item: Box<IndexItem>,
        secret: Zeroizing<Vec<u8>>,
    },
    Delete {
        id: String,
    },
}

enum PromptObjectRef {
    Collection,
    Item(String),
}

#[derive(Clone, Copy)]
struct ApprovalEvent {
    prompt_id: u64,
    approved: bool,
}

enum CompletionResult {
    Paths(Vec<Path<'static>>),
    Path(Path<'static>),
    Empty,
}

struct PromptCompletion {
    prompt_id: u64,
    dismissed: bool,
    result: CompletionResult,
    created: Option<IndexItem>,
    deleted: Option<String>,
}

impl PromptCompletion {
    fn dismissed(prompt_id: u64) -> Self {
        Self {
            prompt_id,
            dismissed: true,
            result: CompletionResult::Empty,
            created: None,
            deleted: None,
        }
    }

    fn message(self) -> Message {
        let path = prompt_path(self.prompt_id);
        let interface = Interface::new("org.freedesktop.Secret.Prompt").expect("valid interface");
        let member = Member::new("Completed").expect("valid signal member");
        let message = Message::signal(&path, &interface, &member);
        if self.dismissed {
            return message.append2(true, Variant(String::new()));
        }
        match self.result {
            CompletionResult::Paths(paths) => message.append2(false, Variant(paths)),
            CompletionResult::Path(path) => message.append2(false, Variant(path)),
            CompletionResult::Empty => message.append2(false, Variant(String::new())),
        }
    }
}

impl Agent {
    fn new(
        vault: UnlockedVault,
        options: SecretServiceOptions,
        approval_sender: mpsc::Sender<ApprovalEvent>,
    ) -> Result<Self, SecretServiceError> {
        let vault = Arc::new(vault);
        let index = match vault.read_secret_service_index()? {
            Some(bytes) => {
                let parsed: Index = serde_json::from_slice(&bytes)
                    .map_err(|error| SecretServiceError::InvalidIndex(error.to_string()))?;
                if parsed.format != INDEX_FORMAT || parsed.version != INDEX_VERSION {
                    return Err(SecretServiceError::InvalidIndex(
                        "unsupported format or version".to_owned(),
                    ));
                }
                parsed
            }
            None => Index::default(),
        };
        Ok(Self {
            vault,
            index: Mutex::new(index),
            sessions: Mutex::new(HashMap::new()),
            grants: Mutex::new(HashMap::new()),
            prompts: Mutex::new(HashMap::new()),
            identities: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            options,
            approval_sender,
            approval_gate: Mutex::new(()),
        })
    }

    fn item_ids(&self) -> Result<Vec<String>, SecretServiceError> {
        Ok(lock(&self.index)?
            .items
            .iter()
            .map(|item| item.id.clone())
            .collect())
    }

    fn remember_identity(&self, owner: &str) {
        let identity = resolve_caller_identity(owner);
        if let Ok(mut identities) = self.identities.lock() {
            identities.insert(owner.to_owned(), identity);
        }
    }

    fn open_session(&self, owner: &str, cipher: SessionCipher) -> Result<Path<'static>, MethodErr> {
        self.remember_identity(owner);
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let path = format!("{SESSION_PREFIX}{id}");
        lock_method(&self.sessions)?.insert(
            path.clone(),
            Session {
                owner: owner.to_owned(),
                cipher,
            },
        );
        dbus_path(&path)
    }

    fn close_session(&self, path: &Path<'_>, owner: &str) -> Result<(), MethodErr> {
        let mut sessions = lock_method(&self.sessions)?;
        let path_key = path.to_string();
        let session = sessions.get(&path_key).ok_or_else(|| no_session(path))?;
        ensure_owner(&session.owner, owner)?;
        sessions.remove(&path_key);
        self.remove_owner_grants(owner)?;
        Ok(())
    }

    fn decrypt_secret(
        &self,
        secret: &Secret,
        owner: &str,
    ) -> Result<Zeroizing<Vec<u8>>, MethodErr> {
        let sessions = lock_method(&self.sessions)?;
        let path_key = secret.0.to_string();
        let session = sessions
            .get(&path_key)
            .ok_or_else(|| no_session(&secret.0))?;
        ensure_owner(&session.owner, owner)?;
        match &session.cipher {
            SessionCipher::Plain => {
                if !secret.1.is_empty() {
                    return Err(MethodErr::invalid_arg(&"plain session parameters"));
                }
                Ok(Zeroizing::new(secret.2.clone()))
            }
            SessionCipher::Dh(key) => {
                if secret.1.len() != AES_BLOCK_BYTES {
                    return Err(MethodErr::invalid_arg(&"AES initialization vector"));
                }
                let plaintext = cbc::Decryptor::<aes::Aes128>::new(
                    key.as_ref().into(),
                    secret.1.as_slice().into(),
                )
                .decrypt_padded_vec_mut::<Pkcs7>(&secret.2)
                .map_err(|_| MethodErr::invalid_arg(&"encrypted Secret payload"))?;
                Ok(Zeroizing::new(plaintext))
            }
        }
    }

    fn encrypt_secret(
        &self,
        session_path: &Path<'static>,
        owner: &str,
        plaintext: &[u8],
        content_type: String,
    ) -> Result<Secret, MethodErr> {
        let sessions = lock_method(&self.sessions)?;
        let path_key = session_path.to_string();
        let session = sessions
            .get(&path_key)
            .ok_or_else(|| no_session(session_path))?;
        ensure_owner(&session.owner, owner)?;
        match &session.cipher {
            SessionCipher::Plain => Ok((
                session_path.clone(),
                Vec::new(),
                plaintext.to_vec(),
                content_type,
            )),
            SessionCipher::Dh(key) => {
                let mut iv = [0_u8; AES_BLOCK_BYTES];
                getrandom::fill(&mut iv).map_err(|error| MethodErr::failed(&error))?;
                let ciphertext =
                    cbc::Encryptor::<aes::Aes128>::new(key.as_ref().into(), (&iv).into())
                        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
                Ok((session_path.clone(), iv.to_vec(), ciphertext, content_type))
            }
        }
    }

    fn search(&self, attributes: &HashMap<String, String>) -> Result<Vec<IndexItem>, MethodErr> {
        let mut index = lock_method(&self.index)?;
        let mut matches: Vec<_> = index
            .items
            .iter()
            .filter(|item| attributes_match(&item.attributes, attributes))
            .cloned()
            .collect();
        if matches.is_empty() {
            if let (Some(service), Some(account)) = (
                attributes.get("service"),
                attributes
                    .get("username")
                    .or_else(|| attributes.get("account")),
            ) {
                if self
                    .vault
                    .contains(service, account)
                    .map_err(vault_method)?
                {
                    let now = unix_time();
                    let item = IndexItem {
                        id: random_id().map_err(vault_method)?,
                        service: service.clone(),
                        account: account.clone(),
                        label: format!("{service}: {account}"),
                        attributes: attributes.clone(),
                        content_type: "application/octet-stream".to_owned(),
                        item_type: "org.freedesktop.Secret.Generic".to_owned(),
                        created: now,
                        modified: now,
                    };
                    index.items.push(item.clone());
                    self.save_index(&index)?;
                    matches.push(item);
                }
            }
        }
        Ok(matches)
    }

    fn item(&self, id: &str) -> Result<IndexItem, MethodErr> {
        lock_method(&self.index)?
            .items
            .iter()
            .find(|item| item.id == id)
            .cloned()
            .ok_or_else(|| no_item(id))
    }

    fn all_items(&self) -> Result<Vec<IndexItem>, MethodErr> {
        Ok(lock_method(&self.index)?.items.clone())
    }

    fn save_index(&self, index: &Index) -> Result<(), MethodErr> {
        let bytes = serde_json::to_vec(index).map_err(|error| MethodErr::failed(&error))?;
        self.vault
            .write_secret_service_index(&bytes)
            .map_err(vault_method)
    }

    fn set_item_secret(
        &self,
        id: &str,
        plaintext: &[u8],
        content_type: String,
    ) -> Result<(), MethodErr> {
        let mut index = lock_method(&self.index)?;
        let mut updated = index.clone();
        let item = updated
            .items
            .iter_mut()
            .find(|item| item.id == id)
            .ok_or_else(|| no_item(id))?;
        let previous = self
            .vault
            .get(&item.service, &item.account)
            .map_err(vault_method)?;
        let service = item.service.clone();
        let account = item.account.clone();
        item.content_type = content_type;
        item.modified = unix_time();
        let bytes = serde_json::to_vec(&updated).map_err(|error| MethodErr::failed(&error))?;

        self.vault
            .set(&service, &account, plaintext)
            .map_err(vault_method)?;
        if let Err(error) = self.vault.write_secret_service_index(&bytes) {
            let rollback = self.vault.set(&service, &account, &previous);
            return Err(transaction_error(&error, rollback.as_ref().err()));
        }
        *index = updated;
        Ok(())
    }

    fn has_grant(&self, owner: &str, resource: &str) -> Result<bool, MethodErr> {
        let now = Instant::now();
        let subject = self.grant_subject(owner)?;
        let mut grants = lock_method(&self.grants)?;
        grants.retain(|_, expires| *expires > now);
        Ok(grants.contains_key(&(subject.clone(), resource.to_owned()))
            || grants.contains_key(&(subject, COLLECTION_RESOURCE.to_owned())))
    }

    fn grant(&self, owner: &str, resource: &str) -> Result<(), MethodErr> {
        let now = Instant::now();
        let subject = self.grant_subject(owner)?;
        let expires = now
            .checked_add(self.options.approval_ttl)
            .ok_or_else(|| MethodErr::failed(&"approval duration is too large"))?;
        lock_method(&self.grants)?.insert((subject, resource.to_owned()), expires);
        Ok(())
    }

    fn remove_owner_grants(&self, owner: &str) -> Result<(), MethodErr> {
        let subject = self.grant_subject(owner)?;
        lock_method(&self.grants)?.retain(|(grant_subject, _), _| grant_subject != &subject);
        Ok(())
    }

    fn disconnect_owner(&self, owner: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.retain(|_, session| session.owner != owner);
        }
        if let Ok(mut prompts) = self.prompts.lock() {
            prompts.retain(|_, prompt| prompt.owner != owner);
        }
        if let Ok(mut identities) = self.identities.lock() {
            identities.remove(owner);
        }
    }

    fn lock_objects(
        &self,
        owner: &str,
        objects: &[Path<'static>],
    ) -> Result<Vec<Path<'static>>, MethodErr> {
        let subject = self.grant_subject(owner)?;
        let mut grants = lock_method(&self.grants)?;
        let mut locked = Vec::new();
        for object in objects {
            match parse_object_path(object)? {
                PromptObjectRef::Collection => {
                    grants.retain(|(grant_subject, _), _| grant_subject != &subject);
                    locked.push(object.clone());
                }
                PromptObjectRef::Item(id) => {
                    grants.remove(&(subject.clone(), id));
                    locked.push(object.clone());
                }
            }
        }
        Ok(locked)
    }

    fn grant_subject(&self, owner: &str) -> Result<String, MethodErr> {
        Ok(lock_method(&self.identities)?.get(owner).map_or_else(
            || format!("bus:{owner}"),
            |identity| identity.grant_subject.clone(),
        ))
    }

    fn create_prompt(
        &self,
        owner: &str,
        action: PromptAction,
    ) -> Result<(u64, Path<'static>), MethodErr> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        lock_method(&self.prompts)?.insert(
            id,
            PendingPrompt {
                owner: owner.to_owned(),
                action,
                started: false,
            },
        );
        Ok((id, prompt_path(id)))
    }

    fn start_prompt(self: &Arc<Self>, id: u64, owner: &str) -> Result<(), MethodErr> {
        {
            let mut prompts = lock_method(&self.prompts)?;
            let prompt = prompts
                .get_mut(&id)
                .ok_or_else(|| MethodErr::no_path(&prompt_path(id)))?;
            ensure_owner(&prompt.owner, owner)?;
            if prompt.started {
                return Err(MethodErr::failed(&"prompt has already started"));
            }
            prompt.started = true;
        }
        let agent = Arc::clone(self);
        thread::Builder::new()
            .name(format!("factorseal-approval-{id}"))
            .spawn(move || {
                let approved = agent.ask_for_approval(id);
                let _ = agent.approval_sender.send(ApprovalEvent {
                    prompt_id: id,
                    approved,
                });
            })
            .map_err(|error| MethodErr::failed(&error))?;
        Ok(())
    }

    fn dismiss_prompt(&self, id: u64, owner: &str) -> Result<(), MethodErr> {
        let prompts = lock_method(&self.prompts)?;
        let prompt = prompts
            .get(&id)
            .ok_or_else(|| MethodErr::no_path(&prompt_path(id)))?;
        ensure_owner(&prompt.owner, owner)?;
        self.approval_sender
            .send(ApprovalEvent {
                prompt_id: id,
                approved: false,
            })
            .map_err(|error| MethodErr::failed(&error))
    }

    fn ask_for_approval(&self, id: u64) -> bool {
        let Ok(_gate) = self.approval_gate.lock() else {
            return false;
        };
        let Ok(prompts) = self.prompts.lock() else {
            return false;
        };
        let Some(prompt) = prompts.get(&id) else {
            return false;
        };
        let summary = self.action_summary(&prompt.action);
        let mut identity = self
            .identities
            .lock()
            .ok()
            .and_then(|identities| identities.get(&prompt.owner).cloned())
            .unwrap_or_else(|| CallerIdentity {
                bus_name: prompt.owner.clone(),
                process_id: None,
                executable: None,
                grant_subject: format!("bus:{}", prompt.owner),
            });
        drop(prompts);
        if identity.process_id.is_none() {
            identity = resolve_caller_identity(&identity.bus_name);
            if let Ok(mut identities) = self.identities.lock() {
                identities.insert(identity.bus_name.clone(), identity.clone());
            }
        }

        let mut tty = match OpenOptions::new().read(true).write(true).open("/dev/tty") {
            Ok(tty) => tty,
            Err(error) => {
                eprintln!("factorseal: cannot request approval without /dev/tty: {error}");
                return false;
            }
        };
        let process = identity.executable.as_ref().map_or_else(
            || identity.bus_name.clone(),
            |path| path.display().to_string(),
        );
        let pid = identity
            .process_id
            .map_or_else(String::new, |pid| format!(" (pid {pid})"));
        let seconds = self.options.approval_ttl.as_secs();
        if writeln!(
            tty,
            "\nFactorSeal request\n  application: {process}{pid}\n  action: {summary}\nAllow for {seconds} seconds? [y/N] "
        )
        .and_then(|()| tty.flush())
        .is_err()
        {
            return false;
        }
        let mut answer = String::new();
        BufReader::new(tty).read_line(&mut answer).is_ok()
            && matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    }

    fn complete_prompt(
        &self,
        event: ApprovalEvent,
    ) -> Result<Option<PromptCompletion>, SecretServiceError> {
        let Some(prompt) = lock(&self.prompts)?.remove(&event.prompt_id) else {
            return Ok(None);
        };
        if !event.approved {
            return Ok(Some(PromptCompletion::dismissed(event.prompt_id)));
        }

        let mut created = None;
        let mut deleted = None;
        let result = match prompt.action {
            PromptAction::Unlock { objects } => {
                let mut paths = Vec::new();
                for object in objects {
                    match object {
                        PromptObjectRef::Collection => {
                            self.grant(&prompt.owner, COLLECTION_RESOURCE)
                                .map_err(method_service)?;
                            paths.push(collection_path());
                        }
                        PromptObjectRef::Item(id) => {
                            self.grant(&prompt.owner, &id).map_err(method_service)?;
                            paths.push(item_path(&id));
                        }
                    }
                }
                CompletionResult::Paths(paths)
            }
            PromptAction::Create { item, secret } => {
                let previous = match self.vault.get(&item.service, &item.account) {
                    Ok(secret) => Some(secret),
                    Err(VaultError::NoEntry) => None,
                    Err(error) => return Err(error.into()),
                };
                let mut index = lock(&self.index)?;
                let mut updated = index.clone();
                if let Some(existing) = updated.items.iter_mut().find(|value| value.id == item.id) {
                    existing.clone_from(&item);
                } else {
                    updated.items.push((*item).clone());
                }
                let bytes = serde_json::to_vec(&updated)
                    .map_err(|error| SecretServiceError::InvalidIndex(error.to_string()))?;

                self.vault.set(&item.service, &item.account, &secret)?;
                if let Err(error) = self.vault.write_secret_service_index(&bytes) {
                    let rollback = restore_entry(
                        &self.vault,
                        &item.service,
                        &item.account,
                        previous.as_ref().map(|value| value.as_slice()),
                    );
                    return Err(service_transaction_error(&error, rollback.as_ref().err()));
                }
                *index = updated;
                self.grant(&prompt.owner, &item.id)
                    .map_err(method_service)?;
                created = Some((*item).clone());
                CompletionResult::Path(item_path(&item.id))
            }
            PromptAction::Delete { id } => {
                let mut index = lock(&self.index)?;
                let item = index
                    .items
                    .iter()
                    .find(|item| item.id == id)
                    .cloned()
                    .ok_or_else(|| {
                        SecretServiceError::InvalidIndex(format!("unknown item {id}"))
                    })?;
                let previous = self.vault.get(&item.service, &item.account)?;
                let mut updated = index.clone();
                updated.items.retain(|item| item.id != id);
                let bytes = serde_json::to_vec(&updated)
                    .map_err(|error| SecretServiceError::InvalidIndex(error.to_string()))?;

                self.vault.delete(&item.service, &item.account)?;
                if let Err(error) = self.vault.write_secret_service_index(&bytes) {
                    let rollback = self.vault.set(&item.service, &item.account, &previous);
                    return Err(service_transaction_error(&error, rollback.as_ref().err()));
                }
                *index = updated;
                deleted = Some(id);
                CompletionResult::Empty
            }
        };
        Ok(Some(PromptCompletion {
            prompt_id: event.prompt_id,
            dismissed: false,
            result,
            created,
            deleted,
        }))
    }

    fn action_summary(&self, action: &PromptAction) -> String {
        match action {
            PromptAction::Unlock { objects } => {
                if objects
                    .iter()
                    .any(|object| matches!(object, PromptObjectRef::Collection))
                {
                    return "access all secrets in the FactorSeal collection".to_owned();
                }
                let labels = self
                    .index
                    .lock()
                    .ok()
                    .map(|index| {
                        objects
                            .iter()
                            .filter_map(|object| {
                                let PromptObjectRef::Item(id) = object else {
                                    return None;
                                };
                                index
                                    .items
                                    .iter()
                                    .find(|item| item.id == *id)
                                    .map(|item| {
                                        format!(
                                            "'{}' ({} / {})",
                                            item.label, item.service, item.account
                                        )
                                    })
                                    .or_else(|| Some(id.clone()))
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                format!(
                    "read or update {} requested secret(s): {}",
                    labels.len(),
                    labels.join(", ")
                )
            }
            PromptAction::Create { item, .. } => {
                format!(
                    "store secret '{}' for {} / {}",
                    item.label, item.service, item.account
                )
            }
            PromptAction::Delete { id } => self
                .index
                .lock()
                .ok()
                .and_then(|index| {
                    index.items.iter().find(|item| item.id == *id).map(|item| {
                        format!(
                            "delete secret '{}' for {} / {}",
                            item.label, item.service, item.account
                        )
                    })
                })
                .unwrap_or_else(|| format!("delete secret {id}")),
        }
    }
}

struct Interfaces {
    service: IfaceToken<ServiceObject>,
    collection: IfaceToken<CollectionObject>,
    item: IfaceToken<ItemObject>,
}

#[allow(clippy::too_many_lines)]
fn register_interfaces(crossroads: &mut Crossroads) -> Interfaces {
    let session = crossroads.register("org.freedesktop.Secret.Session", |builder| {
        builder.method(
            "Close",
            (),
            (),
            |context, object: &mut SessionObject, ()| {
                let owner = sender(context)?;
                ensure_owner(&object.owner, &owner)?;
                object.agent.close_session(context.path(), &owner)?;
                Ok(())
            },
        );
    });

    let prompt = crossroads.register("org.freedesktop.Secret.Prompt", |builder| {
        builder.signal::<(bool, DynVariant), _>("Completed", ("dismissed", "result"));
        builder.method(
            "Prompt",
            ("window_id",),
            (),
            |context, object: &mut PromptObject, (_window_id,): (String,)| {
                let owner = sender(context)?;
                ensure_owner(&object.owner, &owner)?;
                object.agent.start_prompt(object.id, &owner)?;
                Ok(())
            },
        );
        builder.method(
            "Dismiss",
            (),
            (),
            |context, object: &mut PromptObject, ()| {
                let owner = sender(context)?;
                ensure_owner(&object.owner, &owner)?;
                object.agent.dismiss_prompt(object.id, &owner)?;
                Ok(())
            },
        );
    });

    let prompt_for_item = prompt;
    let item = crossroads.register("org.freedesktop.Secret.Item", move |builder| {
        builder.method_with_cr("Delete", (), ("prompt",), move |context, crossroads, ()| {
            let owner = sender(context)?;
            let object = crossroads
                .data_mut::<ItemObject>(context.path())
                .ok_or_else(|| MethodErr::no_path(context.path()))?;
            let agent = Arc::clone(&object.agent);
            let id = object.id.clone();
            let (prompt_id, path) = agent.create_prompt(&owner, PromptAction::Delete { id })?;
            crossroads.insert(
                path.clone(),
                &[prompt_for_item],
                PromptObject {
                    agent,
                    id: prompt_id,
                    owner,
                },
            );
            Ok((path,))
        });
        builder.method(
            "GetSecret",
            ("session",),
            ("secret",),
            |context, object: &mut ItemObject, (session,): (Path<'static>,)| {
                let owner = sender(context)?;
                if !object.agent.has_grant(&owner, &object.id)? {
                    return Err(is_locked());
                }
                let item = object.agent.item(&object.id)?;
                let secret = object
                    .agent
                    .vault
                    .get(&item.service, &item.account)
                    .map_err(vault_method)?;
                Ok((object
                    .agent
                    .encrypt_secret(&session, &owner, &secret, item.content_type)?,))
            },
        );
        builder.method(
            "SetSecret",
            ("secret",),
            (),
            |context, object: &mut ItemObject, (secret,): (Secret,)| {
                let owner = sender(context)?;
                if !object.agent.has_grant(&owner, &object.id)? {
                    return Err(is_locked());
                }
                let plaintext = object.agent.decrypt_secret(&secret, &owner)?;
                object
                    .agent
                    .set_item_secret(&object.id, &plaintext, secret.3)
            },
        );
        builder
            .property::<bool, _>("Locked")
            .get(|context, object| {
                let owner = property_sender(context)?;
                Ok(!object.agent.has_grant(&owner, &object.id)?)
            });
        builder
            .property::<HashMap<String, String>, _>("Attributes")
            .get(|_, object| Ok(object.agent.item(&object.id)?.attributes))
            .set(|context, object, attributes| {
                let owner = property_sender(context)?;
                if !object.agent.has_grant(&owner, &object.id)? {
                    return Err(is_locked());
                }
                let mut index = lock_method(&object.agent.index)?;
                let item = index
                    .items
                    .iter_mut()
                    .find(|item| item.id == object.id)
                    .ok_or_else(|| no_item(&object.id))?;
                let (service, account) = storage_names(&attributes, &item.id)?;
                if service != item.service || account != item.account {
                    return Err(MethodErr::failed(
                        &"changing service or username is not supported",
                    ));
                }
                item.attributes.clone_from(&attributes);
                item.modified = unix_time();
                object.agent.save_index(&index)?;
                Ok(Some(attributes))
            });
        builder
            .property::<String, _>("Label")
            .get(|_, object| Ok(object.agent.item(&object.id)?.label))
            .set(|context, object, label| {
                let owner = property_sender(context)?;
                if !object.agent.has_grant(&owner, &object.id)? {
                    return Err(is_locked());
                }
                let mut index = lock_method(&object.agent.index)?;
                let item = index
                    .items
                    .iter_mut()
                    .find(|item| item.id == object.id)
                    .ok_or_else(|| no_item(&object.id))?;
                item.label.clone_from(&label);
                item.modified = unix_time();
                object.agent.save_index(&index)?;
                Ok(Some(label))
            });
        builder
            .property::<String, _>("Type")
            .get(|_, object| Ok(object.agent.item(&object.id)?.item_type))
            .set(|context, object, item_type| {
                let owner = property_sender(context)?;
                if !object.agent.has_grant(&owner, &object.id)? {
                    return Err(is_locked());
                }
                let mut index = lock_method(&object.agent.index)?;
                let item = index
                    .items
                    .iter_mut()
                    .find(|item| item.id == object.id)
                    .ok_or_else(|| no_item(&object.id))?;
                item.item_type.clone_from(&item_type);
                item.modified = unix_time();
                object.agent.save_index(&index)?;
                Ok(Some(item_type))
            });
        builder
            .property::<u64, _>("Created")
            .get(|_, object| Ok(object.agent.item(&object.id)?.created));
        builder
            .property::<u64, _>("Modified")
            .get(|_, object| Ok(object.agent.item(&object.id)?.modified));
    });

    let prompt_for_collection = prompt;
    let collection = crossroads.register("org.freedesktop.Secret.Collection", move |builder| {
        builder.signal::<(Path<'static>,), _>("ItemCreated", ("item",));
        builder.signal::<(Path<'static>,), _>("ItemDeleted", ("item",));
        builder.signal::<(Path<'static>,), _>("ItemChanged", ("item",));
        builder.method(
            "Delete",
            (),
            ("prompt",),
            |_, _: &mut CollectionObject, ()| -> Result<(Path<'static>,), MethodErr> {
                Err(MethodErr::failed(
                    &"the FactorSeal collection cannot be deleted",
                ))
            },
        );
        builder.method(
            "SearchItems",
            ("attributes",),
            ("results",),
            |_, object: &mut CollectionObject, (attributes,): (HashMap<String, String>,)| {
                let paths: Vec<Path<'static>> = object
                    .0
                    .search(&attributes)?
                    .iter()
                    .map(|item| item_path(&item.id))
                    .collect();
                Ok((paths,))
            },
        );
        builder.method_with_cr(
            "CreateItem",
            ("properties", "secret", "replace"),
            ("item", "prompt"),
            move |context, crossroads, (properties, secret, replace): (PropMap, Secret, bool)| {
                let owner = sender(context)?;
                let object = crossroads
                    .data_mut::<CollectionObject>(context.path())
                    .ok_or_else(|| MethodErr::no_path(context.path()))?;
                let agent = Arc::clone(&object.0);
                let plaintext = agent.decrypt_secret(&secret, &owner)?;
                let label = prop_cast::<String>(&properties, ITEM_LABEL)
                    .cloned()
                    .ok_or_else(|| MethodErr::invalid_arg(&ITEM_LABEL))?;
                let attributes = property_string_map(&properties, ITEM_ATTRIBUTES)?;
                let existing = if replace {
                    agent.search(&attributes)?.into_iter().next()
                } else {
                    None
                };
                let id = existing
                    .as_ref()
                    .map_or_else(random_id, |item| Ok(item.id.clone()))
                    .map_err(vault_method)?;
                let (service, account) = storage_names(&attributes, &id)?;
                if let Some(same_entry) = agent
                    .all_items()?
                    .into_iter()
                    .find(|item| item.service == service && item.account == account)
                {
                    if replace {
                        if existing
                            .as_ref()
                            .is_none_or(|item| item.id != same_entry.id)
                        {
                            return Err(MethodErr::failed(
                                &"replace attributes resolve to a different existing item",
                            ));
                        }
                    } else {
                        return Err(MethodErr::failed(
                            &"FactorSeal already contains this service and account",
                        ));
                    }
                } else if !replace
                    && agent
                        .vault
                        .contains(&service, &account)
                        .map_err(vault_method)?
                {
                    return Err(MethodErr::failed(
                        &"FactorSeal already contains this service and account",
                    ));
                }
                let now = unix_time();
                let item = IndexItem {
                    id,
                    service,
                    account,
                    label,
                    attributes,
                    content_type: secret.3,
                    item_type: existing.as_ref().map_or_else(
                        || "org.freedesktop.Secret.Generic".to_owned(),
                        |item| item.item_type.clone(),
                    ),
                    created: existing.as_ref().map_or(now, |item| item.created),
                    modified: now,
                };
                let (prompt_id, path) = agent.create_prompt(
                    &owner,
                    PromptAction::Create {
                        item: Box::new(item),
                        secret: plaintext,
                    },
                )?;
                crossroads.insert(
                    path.clone(),
                    &[prompt_for_collection],
                    PromptObject {
                        agent,
                        id: prompt_id,
                        owner,
                    },
                );
                Ok((root_path(), path))
            },
        );
        builder
            .property::<Vec<Path<'static>>, _>("Items")
            .get(|_, object| {
                Ok(object
                    .0
                    .all_items()?
                    .iter()
                    .map(|item| item_path(&item.id))
                    .collect())
            });
        builder
            .property::<String, _>("Label")
            .get(|_, _| Ok("FactorSeal".to_owned()))
            .set(|_, _, _| Err(MethodErr::ro_property(&"Label")));
        builder
            .property::<bool, _>("Locked")
            .get(|context, object| {
                let owner = property_sender(context)?;
                Ok(!object.0.has_grant(&owner, COLLECTION_RESOURCE)?)
            });
        builder.property::<u64, _>("Created").get(|_, _| Ok(0));
        builder.property::<u64, _>("Modified").get(|_, _| Ok(0));
    });

    let session_for_service = session;
    let prompt_for_service = prompt;
    let service = crossroads.register("org.freedesktop.Secret.Service", move |builder| {
        builder.signal::<(Path<'static>,), _>("CollectionCreated", ("collection",));
        builder.signal::<(Path<'static>,), _>("CollectionDeleted", ("collection",));
        builder.signal::<(Path<'static>,), _>("CollectionChanged", ("collection",));
        builder.method_with_cr(
            "OpenSession",
            ("algorithm", "input"),
            ("output", "result"),
            move |context, crossroads, (algorithm, input): (String, DynVariant)| {
                let (output, cipher) = negotiate_session(&algorithm, &input)?;
                let owner = sender(context)?;
                let object = crossroads
                    .data_mut::<ServiceObject>(context.path())
                    .ok_or_else(|| MethodErr::no_path(context.path()))?;
                let agent = Arc::clone(&object.0);
                let path = agent.open_session(&owner, cipher)?;
                crossroads.insert(
                    path.clone(),
                    &[session_for_service],
                    SessionObject { agent, owner },
                );
                Ok((output, path))
            },
        );
        builder.method(
            "CreateCollection",
            ("properties", "alias"),
            ("collection", "prompt"),
            |_, _: &mut ServiceObject, (properties, _alias): (PropMap, String)| {
                let _ = prop_cast::<String>(&properties, COLLECTION_LABEL);
                Ok((collection_path(), root_path()))
            },
        );
        builder.method(
            "SearchItems",
            ("attributes",),
            ("unlocked", "locked"),
            |context, object: &mut ServiceObject, (attributes,): (HashMap<String, String>,)| {
                let owner = sender(context)?;
                let mut unlocked = Vec::new();
                let mut locked_items = Vec::new();
                for item in object.0.search(&attributes)? {
                    if object.0.has_grant(&owner, &item.id)? {
                        unlocked.push(item_path(&item.id));
                    } else {
                        locked_items.push(item_path(&item.id));
                    }
                }
                Ok((unlocked, locked_items))
            },
        );
        builder.method_with_cr(
            "Unlock",
            ("objects",),
            ("unlocked", "prompt"),
            move |context, crossroads, (paths,): (Vec<Path<'static>>,)| {
                let owner = sender(context)?;
                let object = crossroads
                    .data_mut::<ServiceObject>(context.path())
                    .ok_or_else(|| MethodErr::no_path(context.path()))?;
                let agent = Arc::clone(&object.0);
                let mut immediate = Vec::new();
                let mut pending = Vec::new();
                for path in paths {
                    let object = parse_object_path(&path)?;
                    let resource = match &object {
                        PromptObjectRef::Collection => COLLECTION_RESOURCE,
                        PromptObjectRef::Item(id) => id,
                    };
                    if agent.has_grant(&owner, resource)? {
                        immediate.push(path);
                    } else {
                        pending.push(object);
                    }
                }
                if pending.is_empty() {
                    return Ok((immediate, root_path()));
                }
                let (prompt_id, path) =
                    agent.create_prompt(&owner, PromptAction::Unlock { objects: pending })?;
                crossroads.insert(
                    path.clone(),
                    &[prompt_for_service],
                    PromptObject {
                        agent,
                        id: prompt_id,
                        owner,
                    },
                );
                Ok((immediate, path))
            },
        );
        builder.method(
            "Lock",
            ("objects",),
            ("locked", "prompt"),
            |context, object: &mut ServiceObject, (paths,): (Vec<Path<'static>>,)| {
                let owner = sender(context)?;
                let locked = object.0.lock_objects(&owner, &paths)?;
                Ok((locked, root_path()))
            },
        );
        builder.method(
            "GetSecrets",
            ("items", "session"),
            ("secrets",),
            |context,
             object: &mut ServiceObject,
             (paths, session): (Vec<Path<'static>>, Path<'static>)| {
                let owner = sender(context)?;
                let mut secrets = HashMap::new();
                for path in paths {
                    let PromptObjectRef::Item(id) = parse_object_path(&path)? else {
                        return Err(MethodErr::invalid_arg(&path));
                    };
                    if !object.0.has_grant(&owner, &id)? {
                        continue;
                    }
                    let item = object.0.item(&id)?;
                    let secret = object
                        .0
                        .vault
                        .get(&item.service, &item.account)
                        .map_err(vault_method)?;
                    secrets.insert(
                        path,
                        object
                            .0
                            .encrypt_secret(&session, &owner, &secret, item.content_type)?,
                    );
                }
                Ok((secrets,))
            },
        );
        builder.method(
            "ReadAlias",
            ("name",),
            ("collection",),
            |_, _: &mut ServiceObject, (name,): (String,)| {
                if name.is_empty() {
                    Ok((root_path(),))
                } else if name == "default" {
                    Ok((default_alias_path(),))
                } else {
                    Ok((collection_path(),))
                }
            },
        );
        builder.method(
            "SetAlias",
            ("name", "collection"),
            (),
            |_, _: &mut ServiceObject, (_name, collection): (String, Path<'static>)| {
                if collection != collection_path() && collection != default_alias_path() {
                    return Err(MethodErr::invalid_arg(&collection));
                }
                Ok(())
            },
        );
        builder
            .property::<Vec<Path<'static>>, _>("Collections")
            .get(|_, _| Ok(vec![collection_path()]));
    });

    Interfaces {
        service,
        collection,
        item,
    }
}

fn sender(context: &Context) -> Result<String, MethodErr> {
    context
        .message()
        .sender()
        .map(|sender| sender.to_string())
        .ok_or_else(|| MethodErr::failed(&"D-Bus caller has no unique name"))
}

fn property_sender(context: &PropContext) -> Result<String, MethodErr> {
    context
        .message()
        .and_then(Message::sender)
        .map(|sender| sender.to_string())
        .ok_or_else(|| MethodErr::failed(&"D-Bus caller has no unique name"))
}

fn ensure_owner(expected: &str, actual: &str) -> Result<(), MethodErr> {
    if expected == actual {
        Ok(())
    } else {
        Err(MethodErr::failed(
            &"Secret Service object belongs to another D-Bus caller",
        ))
    }
}

fn attributes_match(item: &HashMap<String, String>, query: &HashMap<String, String>) -> bool {
    query
        .iter()
        .all(|(key, value)| item.get(key) == Some(value))
}

fn storage_names(
    attributes: &HashMap<String, String>,
    id: &str,
) -> Result<(String, String), MethodErr> {
    let service = attributes
        .get("service")
        .cloned()
        .unwrap_or_else(|| "secret-service".to_owned());
    let account = attributes
        .get("username")
        .or_else(|| attributes.get("account"))
        .cloned()
        .unwrap_or_else(|| id.to_owned());
    if service.is_empty() || account.is_empty() {
        return Err(MethodErr::invalid_arg(&"empty service or account"));
    }
    Ok((service, account))
}

fn property_string_map(
    properties: &PropMap,
    name: &str,
) -> Result<HashMap<String, String>, MethodErr> {
    if let Some(map) = prop_cast::<HashMap<String, String>>(properties, name) {
        return Ok(map.clone());
    }
    let value = properties
        .get(name)
        .ok_or_else(|| MethodErr::invalid_arg(&name))?;
    let mut values = value
        .0
        .as_iter()
        .ok_or_else(|| MethodErr::invalid_arg(&name))?;
    let mut result = HashMap::new();
    while let Some(key) = values.next() {
        let value = values.next().ok_or_else(|| MethodErr::invalid_arg(&name))?;
        let key = key.as_str().ok_or_else(|| MethodErr::invalid_arg(&name))?;
        let value = value
            .as_str()
            .ok_or_else(|| MethodErr::invalid_arg(&name))?;
        result.insert(key.to_owned(), value.to_owned());
    }
    Ok(result)
}

fn parse_object_path(path: &Path<'_>) -> Result<PromptObjectRef, MethodErr> {
    let value: &str = path.as_ref();
    if matches!(value, COLLECTION_PATH | DEFAULT_ALIAS_PATH) {
        return Ok(PromptObjectRef::Collection);
    }
    if let Some(id) = value.strip_prefix(ITEM_PREFIX) {
        if !id.is_empty() {
            return Ok(PromptObjectRef::Item(id.to_owned()));
        }
    }
    Err(MethodErr::no_path(path))
}

fn dbus_process_id(owner: &str) -> Option<u32> {
    let connection = dbus::blocking::Connection::new_session().ok()?;
    let proxy = connection.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        Duration::from_secs(2),
    );
    let result: Result<(u32,), _> = proxy.method_call(
        "org.freedesktop.DBus",
        "GetConnectionUnixProcessID",
        (owner,),
    );
    result.ok().map(|value| value.0)
}

fn resolve_caller_identity(owner: &str) -> CallerIdentity {
    let process_id = dbus_process_id(owner);
    let process_start_time = process_id.and_then(proc_start_time);
    let executable = process_id.and_then(|id| std::fs::read_link(format!("/proc/{id}/exe")).ok());
    let grant_subject = match (process_id, process_start_time) {
        (Some(process_id), Some(start_time)) => {
            format!("process:{process_id}:start:{start_time}")
        }
        _ => format!("bus:{owner}"),
    };
    CallerIdentity {
        bus_name: owner.to_owned(),
        process_id,
        executable,
        grant_subject,
    }
}

fn proc_start_time(process_id: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{process_id}/stat")).ok()?;
    let (_, fields) = stat.rsplit_once(')')?;
    fields.split_whitespace().nth(19)?.parse().ok()
}

fn negotiate_session(
    algorithm: &str,
    input: &DynVariant,
) -> Result<(DynVariant, SessionCipher), MethodErr> {
    match algorithm {
        ALGORITHM_PLAIN => Ok((
            Variant(Box::new(String::new()) as Box<dyn RefArg>),
            SessionCipher::Plain,
        )),
        ALGORITHM_DH => {
            let client_bytes = dbus::arg::cast::<Vec<u8>>(&input.0)
                .ok_or_else(|| MethodErr::invalid_arg(&"DH public key"))?;
            let prime = BigUint::from_bytes_be(&DH_PRIME_BYTES);
            let client_public = BigUint::from_bytes_be(client_bytes);
            let two = BigUint::from(2_u8);
            if client_public < two || client_public > &prime - &two {
                return Err(MethodErr::invalid_arg(&"DH public key range"));
            }

            let mut private_bytes = Zeroizing::new([0_u8; DH_BYTES]);
            getrandom::fill(&mut *private_bytes).map_err(|error| MethodErr::failed(&error))?;
            let private = BigUint::from_bytes_be(&*private_bytes);
            let server_public = two.modpow(&private, &prime);
            let shared = client_public.modpow(&private, &prime);
            let shared = pad_dh_value(&shared)?;
            let mut key = Zeroizing::new([0_u8; AES_KEY_BYTES]);
            Hkdf::<Sha256>::new(None, &shared)
                .expand(&[], &mut *key)
                .map_err(|_| MethodErr::failed(&"could not derive Secret Service session key"))?;
            let output = pad_dh_value(&server_public)?;
            Ok((
                Variant(Box::new(output) as Box<dyn RefArg>),
                SessionCipher::Dh(key),
            ))
        }
        _ => Err(MethodErr::failed(&format!(
            "unsupported Secret Service session algorithm `{algorithm}`"
        ))),
    }
}

fn pad_dh_value(value: &BigUint) -> Result<Vec<u8>, MethodErr> {
    let bytes = value.to_bytes_be();
    if bytes.len() > DH_BYTES {
        return Err(MethodErr::invalid_arg(&"oversized DH value"));
    }
    let mut padded = vec![0_u8; DH_BYTES - bytes.len()];
    padded.extend_from_slice(&bytes);
    Ok(padded)
}

fn random_id() -> Result<String, VaultError> {
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

fn item_path(id: &str) -> Path<'static> {
    Path::new(format!("{ITEM_PREFIX}{id}")).expect("hex item id is a valid D-Bus path")
}

fn collection_signal(member: &str, item: Path<'static>) -> Message {
    let path = collection_path();
    let interface =
        Interface::new("org.freedesktop.Secret.Collection").expect("valid collection interface");
    let member = Member::new(member.to_owned()).expect("valid collection signal");
    Message::signal(&path, &interface, &member).append1(item)
}

fn prompt_path(id: u64) -> Path<'static> {
    Path::new(format!("{PROMPT_PREFIX}{id}")).expect("numeric prompt id is a valid D-Bus path")
}

fn collection_path() -> Path<'static> {
    Path::new(COLLECTION_PATH).expect("valid collection path")
}

fn default_alias_path() -> Path<'static> {
    Path::new(DEFAULT_ALIAS_PATH).expect("valid alias path")
}

fn root_path() -> Path<'static> {
    Path::new(ROOT_PATH).expect("valid root path")
}

fn dbus_path(value: &str) -> Result<Path<'static>, MethodErr> {
    Path::new(value.to_owned()).map_err(|error| MethodErr::invalid_arg(&error))
}

#[allow(clippy::needless_pass_by_value)]
fn vault_method(error: VaultError) -> MethodErr {
    MethodErr::failed(&error)
}

#[allow(clippy::needless_pass_by_value)]
fn method_service(error: MethodErr) -> SecretServiceError {
    SecretServiceError::InvalidIndex(error.to_string())
}

fn restore_entry(
    vault: &UnlockedVault,
    service: &str,
    account: &str,
    previous: Option<&[u8]>,
) -> Result<(), VaultError> {
    if let Some(previous) = previous {
        vault.set(service, account, previous)
    } else {
        match vault.delete(service, account) {
            Ok(()) | Err(VaultError::NoEntry) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn transaction_error(error: &VaultError, rollback: Option<&VaultError>) -> MethodErr {
    MethodErr::failed(&transaction_message(error, rollback))
}

fn service_transaction_error(
    error: &VaultError,
    rollback: Option<&VaultError>,
) -> SecretServiceError {
    SecretServiceError::InvalidIndex(transaction_message(error, rollback))
}

fn transaction_message(error: &VaultError, rollback: Option<&VaultError>) -> String {
    rollback.map_or_else(
        || format!("could not commit Secret Service metadata: {error}"),
        |rollback| {
            format!(
                "could not commit Secret Service metadata: {error}; entry rollback also failed: {rollback}"
            )
        },
    )
}

fn no_item(id: &str) -> MethodErr {
    (
        "org.freedesktop.Secret.Error.NoSuchObject",
        format!("no Secret Service item {id}"),
    )
        .into()
}

fn no_session(path: &Path<'_>) -> MethodErr {
    (
        "org.freedesktop.Secret.Error.NoSuchObject",
        format!("no Secret Service session {path}"),
    )
        .into()
}

fn is_locked() -> MethodErr {
    (
        "org.freedesktop.Secret.Error.IsLocked",
        "the application has no active FactorSeal grant",
    )
        .into()
}

fn lock<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, SecretServiceError> {
    mutex.lock().map_err(|_| SecretServiceError::Poisoned)
}

fn lock_method<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, MethodErr> {
    mutex
        .lock()
        .map_err(|_| MethodErr::failed(&"Secret Service state lock was poisoned"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Vault;

    fn agent() -> (tempfile::TempDir, Arc<Agent>) {
        let directory = tempfile::tempdir().unwrap();
        let vault = Vault::create_for_test(directory.path().join("vault")).unwrap();
        let (sender, _receiver) = mpsc::channel();
        let agent = Agent::new(vault, SecretServiceOptions::default(), sender).unwrap();
        (directory, Arc::new(agent))
    }

    #[test]
    fn subset_attribute_matching() {
        let attributes = HashMap::from([
            ("service".to_owned(), "example".to_owned()),
            ("username".to_owned(), "alice".to_owned()),
            ("extra".to_owned(), "value".to_owned()),
        ]);
        assert!(attributes_match(
            &attributes,
            &HashMap::from([("service".to_owned(), "example".to_owned())])
        ));
        assert!(!attributes_match(
            &attributes,
            &HashMap::from([("service".to_owned(), "other".to_owned())])
        ));
    }

    #[test]
    fn generic_items_get_stable_internal_names() {
        let (service, account) = storage_names(&HashMap::new(), "abc").unwrap();
        assert_eq!(service, "secret-service");
        assert_eq!(account, "abc");
    }

    #[test]
    fn grants_are_bound_to_the_callers_bus_connection() {
        let (_directory, agent) = agent();
        agent.grant(":1.10", "item").unwrap();

        assert!(agent.has_grant(":1.10", "item").unwrap());
        assert!(!agent.has_grant(":1.11", "item").unwrap());
        assert!(!agent.has_grant(":1.10", "other").unwrap());
    }

    #[test]
    fn reconnects_from_the_same_process_reuse_the_grant() {
        let (_directory, agent) = agent();
        let subject = "process:42:start:100".to_owned();
        let mut identities = agent.identities.lock().unwrap();
        for owner in [":1.10", ":1.11"] {
            identities.insert(
                owner.to_owned(),
                CallerIdentity {
                    bus_name: owner.to_owned(),
                    process_id: Some(42),
                    executable: Some(PathBuf::from("/example")),
                    grant_subject: subject.clone(),
                },
            );
        }
        drop(identities);

        agent.grant(":1.10", "item").unwrap();
        assert!(agent.has_grant(":1.11", "item").unwrap());
    }

    #[test]
    fn exact_search_imports_an_existing_cli_entry() {
        let (_directory, agent) = agent();
        agent.vault.set("example", "alice", b"secret").unwrap();
        let attributes = HashMap::from([
            ("target".to_owned(), "default".to_owned()),
            ("service".to_owned(), "example".to_owned()),
            ("username".to_owned(), "alice".to_owned()),
        ]);

        let found = agent.search(&attributes).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].service, "example");
        assert_eq!(found[0].account, "alice");
        assert!(agent.vault.read_secret_service_index().unwrap().is_some());
    }

    #[test]
    fn encrypted_session_derives_the_same_key_as_the_client() {
        let prime = BigUint::from_bytes_be(&DH_PRIME_BYTES);
        let generator = BigUint::from(2_u8);
        let client_private = BigUint::from(42_u8);
        let client_public = generator.modpow(&client_private, &prime);
        let input = Variant(Box::new(pad_dh_value(&client_public).unwrap()) as Box<dyn RefArg>);

        let (output, cipher) = negotiate_session(ALGORITHM_DH, &input).unwrap();
        let server_public = dbus::arg::cast::<Vec<u8>>(&output.0).unwrap();
        let shared = BigUint::from_bytes_be(server_public).modpow(&client_private, &prime);
        let shared = pad_dh_value(&shared).unwrap();
        let mut expected = [0_u8; AES_KEY_BYTES];
        Hkdf::<Sha256>::new(None, &shared)
            .expand(&[], &mut expected)
            .unwrap();

        let SessionCipher::Dh(actual) = cipher else {
            panic!("expected encrypted session");
        };
        assert_eq!(*actual, expected);
    }
}

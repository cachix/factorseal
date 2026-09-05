use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use factorseal::{
    DocumentKind, GrantPermission, MAX_LIST_PAGE_SIZE, NativeVaultClient, SecretAddress,
    UnlockCredentials, UnlockFactorKind, UnlockGroup, UnlockPolicy, UnsealLeasePolicy, Vault,
    VaultAction, VaultArchive, VaultArchiveEntry, VaultClient, VaultCryptoProfile,
    VaultEntryImportStatus, VaultEntryMetadata, VaultMetadata, VaultRequest, VaultResponseBody,
    VaultService, WireSecret, WireSecretAddress, decrypt_vault_archive, encrypt_vault_archive,
};
use zeroize::Zeroizing;

use factorseal::transfer::{PersonalSecret, TransferFormat, export_manager, import_manager};

#[cfg(target_os = "linux")]
use factorseal::{
    LinuxVaultLifecycle as NativeLifecycle, LinuxVaultOptions,
    linux_caller_identity_for_executable, serve_linux_vault_with_lifecycle,
};
#[cfg(target_os = "macos")]
use factorseal::{
    MacosVaultLifecycle as NativeLifecycle, MacosVaultOptions,
    macos_caller_identity_for_executable, serve_macos_vault_with_lifecycle,
};
#[cfg(target_os = "windows")]
use factorseal::{
    WindowsVaultLifecycle as NativeLifecycle, WindowsVaultOptions, default_windows_pipe_name,
    serve_windows_vault_with_lifecycle, windows_caller_identity_for_executable,
};

const METADATA_FILE: &str = "factorseal.json";
const DESKTOP_CONTROL_NAMESPACE: &[u8] = b"factorseal/desktop-control/v1";
pub(crate) const PERSONAL_SECRET_NAMESPACE: &[u8] = b"factorseal/personal-secrets/v1";
const CLI_CONTROL_NAMESPACE: &[u8] = b"factorseal/cli-control/v1";
const CLI_EXECUTABLE_ENV: &str = "FACTORSEAL_CLI_EXECUTABLE";
const DESKTOP_PROJECT_PERMISSIONS: [GrantPermission; 4] = [
    GrantPermission::List,
    GrantPermission::Get,
    GrantPermission::Put,
    GrantPermission::Delete,
];
#[cfg(any(target_os = "linux", target_os = "macos"))]
const DEFAULT_SOCKET: &str = "factorseal.sock";

#[derive(Clone, Debug)]
pub(crate) struct RuntimeConfig {
    pub(crate) root: PathBuf,
    pub(crate) socket: Option<PathBuf>,
    pub(crate) lease: UnsealLeasePolicy,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct VaultContents {
    pub(crate) entries: Vec<VaultEntryMetadata>,
    pub(crate) permissions: Vec<factorseal::Permission>,
    pub(crate) secret_service_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct TransferSummary {
    pub(crate) added: usize,
    pub(crate) replaced: usize,
    pub(crate) kept_existing: usize,
}

impl TransferSummary {
    pub(crate) const fn processed(self) -> usize {
        self.added + self.replaced + self.kept_existing
    }

    fn record(&mut self, status: VaultEntryImportStatus) {
        match status {
            VaultEntryImportStatus::Added => self.added += 1,
            VaultEntryImportStatus::Replaced => self.replaced += 1,
            VaultEntryImportStatus::KeptExisting => self.kept_existing += 1,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Snapshot {
    Uninitialized {
        error: Option<String>,
    },
    Initializing,
    Sealed {
        metadata: VaultMetadata,
        error: Option<String>,
    },
    Unlocking {
        metadata: VaultMetadata,
        group: UnlockGroup,
    },
    Sealing {
        metadata: VaultMetadata,
    },
    Unsealed {
        metadata: VaultMetadata,
        idle_deadline: u64,
        absolute_deadline: u64,
        owned: bool,
        contents: VaultContents,
        contents_error: Option<String>,
        error: Option<String>,
    },
    Error(String),
}

impl Snapshot {
    pub(crate) fn metadata(&self) -> Option<&VaultMetadata> {
        match self {
            Self::Sealed { metadata, .. }
            | Self::Unlocking { metadata, .. }
            | Self::Sealing { metadata }
            | Self::Unsealed { metadata, .. } => Some(metadata),
            Self::Uninitialized { .. } | Self::Initializing | Self::Error(_) => None,
        }
    }
}

pub(crate) struct DesktopRuntime {
    config: RuntimeConfig,
    events: smol::channel::Sender<Snapshot>,
    service: Mutex<Option<Arc<VaultService>>>,
    unlock_in_progress: AtomicBool,
}

impl DesktopRuntime {
    pub(crate) fn new(config: RuntimeConfig) -> (Arc<Self>, smol::channel::Receiver<Snapshot>) {
        let (events, receiver) = smol::channel::bounded(16);
        (
            Arc::new(Self {
                config,
                events,
                service: Mutex::new(None),
                unlock_in_progress: AtomicBool::new(false),
            }),
            receiver,
        )
    }

    pub(crate) fn inspect(&self) -> Snapshot {
        if !self.config.root.join(METADATA_FILE).is_file() {
            return Snapshot::Uninitialized { error: None };
        }
        let metadata = match Vault::inspect(&self.config.root) {
            Ok(metadata) => metadata,
            Err(error) => return Snapshot::Error(error.to_string()),
        };
        match live_status(&self.config, &metadata) {
            Ok(Some((idle_deadline, absolute_deadline))) => {
                let (contents, contents_error) = match load_vault_contents_from_client(
                    &native_client(&self.config, &metadata),
                ) {
                    Ok(contents) => (contents, None),
                    Err(error) => (VaultContents::default(), Some(error)),
                };
                Snapshot::Unsealed {
                    metadata,
                    idle_deadline,
                    absolute_deadline,
                    owned: false,
                    contents,
                    contents_error,
                    error: None,
                }
            }
            Ok(None) => Snapshot::Sealed {
                metadata,
                error: None,
            },
            Err(error) => Snapshot::Uninitialized { error: Some(error) },
        }
    }

    pub(crate) fn unlock(
        self: &Arc<Self>,
        metadata: VaultMetadata,
        group: UnlockGroup,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<(), &'static str> {
        if self
            .unlock_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("an unlock attempt is already running");
        }
        crate::timing::begin_unlock();
        let runtime = Arc::clone(self);
        let event_metadata = metadata.clone();
        let event_group = group.clone();
        let _ = self.events.try_send(Snapshot::Unlocking {
            metadata: event_metadata,
            group: event_group,
        });
        if std::thread::Builder::new()
            .name("factorseal-desktop-agent".to_owned())
            .spawn(move || {
                crate::timing::mark_unlock("worker_started", "ok");
                runtime.run_unsealed(metadata, &group, &password);
            })
            .is_err()
        {
            self.unlock_in_progress.store(false, Ordering::Release);
            crate::timing::finish_unlock("worker_started", "error");
            return Err("could not start the unlock worker");
        }
        Ok(())
    }

    pub(crate) fn initialize(
        self: &Arc<Self>,
        policy: UnlockPolicy,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<(), &'static str> {
        if self
            .unlock_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("an initialization or unlock attempt is already running");
        }
        let runtime = Arc::clone(self);
        let _ = self.events.try_send(Snapshot::Initializing);
        if std::thread::Builder::new()
            .name("factorseal-desktop-initialize".to_owned())
            .spawn(move || runtime.run_initialization(&policy, &password))
            .is_err()
        {
            self.unlock_in_progress.store(false, Ordering::Release);
            return Err("could not start the initialization worker");
        }
        Ok(())
    }

    pub(crate) fn seal(&self) -> Result<(), String> {
        let service = self
            .service
            .lock()
            .map_err(|_| "the desktop runtime lock is unavailable".to_owned())?
            .clone();
        let Some(service) = service else {
            return Err("this Desktop instance does not own the running agent".to_owned());
        };
        service.seal().map_err(|error| error.to_string())
    }

    pub(crate) fn put_personal_secret(
        &self,
        name: String,
        value: &Zeroizing<Vec<u8>>,
    ) -> Result<VaultContents, String> {
        let metadata = Vault::inspect(&self.config.root).map_err(|error| error.to_string())?;
        let secret = PersonalSecret::generic(
            name.clone(),
            String::from_utf8(value.to_vec())
                .map_err(|_| "personal secret value is not valid UTF-8".to_owned())?,
        );
        let encoded = secret.encode().map_err(|error| error.to_string())?;
        let request = VaultRequest::new(VaultAction::Put {
            namespace: PERSONAL_SECRET_NAMESPACE.to_vec(),
            address: WireSecretAddress::new(name, None),
            value: WireSecret::new(encoded.to_vec()),
            evict_at: None,
        })
        .map_err(|error| error.to_string())?;
        match self.request_live(&metadata, request)? {
            VaultResponseBody::Stored => self.load_live_contents(&metadata),
            _ => Err("vault returned an unexpected personal-secret response".to_owned()),
        }
    }

    pub(crate) fn export_native_archive(
        &self,
        metadata: &VaultMetadata,
        entries: &[VaultEntryMetadata],
        passphrase: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut archived = Vec::new();
        for entry in entries.iter().filter(|entry| portable_entry(entry)) {
            let request = VaultRequest::new(VaultAction::ExportVaultEntry {
                entry: entry.clone(),
            })
            .map_err(|error| error.to_string())?;
            let VaultResponseBody::VaultEntrySecret { value, evict_at } =
                self.request_live(metadata, request)?
            else {
                return Err("vault returned an unexpected archive response".to_owned());
            };
            archived.push(VaultArchiveEntry {
                metadata: entry.clone(),
                value,
                evict_at,
            });
        }
        let archive = VaultArchive::new(unix_time()?, archived);
        encrypt_vault_archive(&archive, passphrase).map_err(|error| error.to_string())
    }

    pub(crate) fn import_native_archive(
        &self,
        metadata: &VaultMetadata,
        bytes: &[u8],
        passphrase: &[u8],
        replace_existing: bool,
    ) -> Result<(TransferSummary, VaultContents), String> {
        let archive =
            decrypt_vault_archive(bytes, passphrase).map_err(|error| error.to_string())?;
        let now = unix_time()?;
        if archive
            .entries
            .iter()
            .any(|entry| entry.evict_at.is_some_and(|deadline| deadline < now))
        {
            return Err("archive contains an entry that has already expired".to_owned());
        }
        let mut summary = TransferSummary::default();
        for entry in archive.entries {
            let request = VaultRequest::new(VaultAction::ImportVaultEntry {
                entry: entry.metadata,
                value: entry.value,
                evict_at: entry.evict_at,
                replace_existing,
            })
            .map_err(|error| error.to_string())?;
            let VaultResponseBody::VaultEntryImported { status } =
                self.request_live(metadata, request)?
            else {
                return Err("vault returned an unexpected archive-import response".to_owned());
            };
            summary.record(status);
        }
        Ok((summary, self.load_live_contents(metadata)?))
    }

    pub(crate) fn export_password_manager(
        &self,
        metadata: &VaultMetadata,
        entries: &[VaultEntryMetadata],
        format: TransferFormat,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let secrets = self.read_personal_secrets(metadata, entries)?;
        export_manager(format, &secrets).map_err(|error| error.to_string())
    }

    pub(crate) fn import_password_manager(
        &self,
        metadata: &VaultMetadata,
        bytes: &[u8],
        format: TransferFormat,
        replace_existing: bool,
    ) -> Result<(TransferSummary, VaultContents), String> {
        let secrets = import_manager(format, bytes).map_err(|error| error.to_string())?;
        let contents = self.load_live_contents(metadata)?;
        let mut occupied = contents
            .entries
            .iter()
            .filter(|entry| is_personal_entry(entry))
            .filter_map(|entry| entry.address.as_local().map(|(item, _)| item.to_owned()))
            .collect::<Vec<_>>();
        let mut source_names = HashMap::<String, usize>::new();
        let mut prepared = Vec::with_capacity(secrets.len());
        for secret in secrets {
            let occurrence = source_names.entry(secret.title.clone()).or_default();
            *occurrence += 1;
            let address_name = if *occurrence == 1 {
                secret.title.clone()
            } else {
                unique_personal_name(&secret.title, &occupied)
            };
            occupied.push(address_name.clone());
            let value = secret.encode().map_err(|error| error.to_string())?;
            let entry = VaultEntryMetadata {
                document_kind: DocumentKind::LocalKeyring,
                partition: PERSONAL_SECRET_NAMESPACE.to_vec(),
                address: SecretAddress::new(address_name, None)
                    .map_err(|error| error.to_string())?,
            };
            prepared.push((entry, WireSecret::new(value.to_vec())));
        }
        let mut summary = TransferSummary::default();
        for (entry, value) in prepared {
            let request = VaultRequest::new(VaultAction::ImportVaultEntry {
                entry,
                value,
                evict_at: None,
                replace_existing,
            })
            .map_err(|error| error.to_string())?;
            let VaultResponseBody::VaultEntryImported { status } =
                self.request_live(metadata, request)?
            else {
                return Err("vault returned an unexpected password-import response".to_owned());
            };
            summary.record(status);
        }
        Ok((summary, self.load_live_contents(metadata)?))
    }

    fn read_personal_secrets(
        &self,
        metadata: &VaultMetadata,
        entries: &[VaultEntryMetadata],
    ) -> Result<Vec<PersonalSecret>, String> {
        entries
            .iter()
            .filter(|entry| is_personal_entry(entry))
            .map(|entry| {
                let title = entry
                    .address
                    .as_local()
                    .map(|(item, _)| item)
                    .ok_or_else(|| "personal secret has an invalid address".to_owned())?;
                let request = VaultRequest::new(VaultAction::ExportVaultEntry {
                    entry: entry.clone(),
                })
                .map_err(|error| error.to_string())?;
                let VaultResponseBody::VaultEntrySecret { value, .. } =
                    self.request_live(metadata, request)?
                else {
                    return Err("vault returned an unexpected personal-secret response".to_owned());
                };
                PersonalSecret::decode(title, value.expose()).map_err(|error| error.to_string())
            })
            .collect()
    }

    fn load_live_contents(&self, metadata: &VaultMetadata) -> Result<VaultContents, String> {
        let service = self
            .service
            .lock()
            .map_err(|_| "the desktop runtime lock is unavailable".to_owned())?
            .clone();
        service.map_or_else(
            || load_vault_contents_from_client(&native_client(&self.config, metadata)),
            |service| load_vault_contents_from_service(&service),
        )
    }

    fn request_live(
        &self,
        metadata: &VaultMetadata,
        request: VaultRequest,
    ) -> Result<VaultResponseBody, String> {
        let service = self
            .service
            .lock()
            .map_err(|_| "the desktop runtime lock is unavailable".to_owned())?
            .clone();
        if let Some(service) = service {
            let executable = std::env::current_exe().map_err(|error| error.to_string())?;
            let caller = current_executable_identity(&executable)?;
            return service
                .handle(&caller, request, unix_time()?)
                .result
                .map_err(|error| error.message);
        }
        native_client(&self.config, metadata)
            .request(&request)
            .map_err(|error| error.to_string())?
            .result
            .map_err(|error| error.message)
    }

    pub(crate) fn start_seal(self: &Arc<Self>, metadata: VaultMetadata) -> Result<(), String> {
        let service = self
            .service
            .lock()
            .map_err(|_| "the desktop runtime lock is unavailable".to_owned())?
            .clone();
        let Some(service) = service else {
            return Err("this Desktop instance does not own the running agent".to_owned());
        };
        let runtime = Arc::clone(self);
        std::thread::Builder::new()
            .name("factorseal-desktop-seal".to_owned())
            .spawn(move || {
                let error = service.seal().err().map(|error| error.to_string());
                let _ = runtime
                    .events
                    .send_blocking(Snapshot::Sealed { metadata, error });
            })
            .map(drop)
            .map_err(|error| format!("could not start the sealing worker: {error}"))
    }

    fn run_unsealed(
        self: Arc<Self>,
        metadata: VaultMetadata,
        group: &UnlockGroup,
        password: &[u8],
    ) {
        let result = self.open_and_serve(&metadata, group, password);
        if result.is_err() {
            crate::timing::finish_unlock("failed", "error");
        }
        if let Ok(mut service) = self.service.lock() {
            *service = None;
        }
        self.unlock_in_progress.store(false, Ordering::Release);
        let _ = self.events.try_send(Snapshot::Sealed {
            metadata,
            error: result.err(),
        });
    }

    fn run_initialization(self: Arc<Self>, policy: &UnlockPolicy, password: &[u8]) {
        let result = self.initialize_inner(policy, password);
        self.unlock_in_progress.store(false, Ordering::Release);
        let snapshot = match result {
            Ok(metadata) => Snapshot::Sealed {
                metadata,
                error: None,
            },
            Err(error) => Snapshot::Error(error),
        };
        let _ = self.events.try_send(snapshot);
    }

    fn initialize_inner(
        &self,
        policy: &UnlockPolicy,
        password: &[u8],
    ) -> Result<VaultMetadata, String> {
        let lifecycle = new_lifecycle().map_err(|error| error.to_string())?;
        lifecycle.arm().map_err(|error| error.to_string())?;
        let credentials = if policy
            .groups()
            .iter()
            .any(|group| group.requires(UnlockFactorKind::Password))
        {
            UnlockCredentials::with_password(password)
        } else {
            UnlockCredentials::none()
        };
        let unsealed = match Vault::prepare_with_unlock_policy_and_profile(
            &self.config.root,
            policy,
            credentials,
            VaultCryptoProfile::Default,
        ) {
            Ok(unsealed) => unsealed,
            Err(error) => {
                lifecycle.disarm();
                return Err(error.to_string());
            }
        };
        let result = (|| {
            let metadata = unsealed.public().clone();
            let now = unix_time()?;
            let service = VaultService::open(
                &self.config.root,
                unsealed,
                now,
                UnsealLeasePolicy::default(),
            )
            .map_err(|error| error.to_string())?;
            authorize_desktop(&service, now)?;
            service.seal().map_err(|error| error.to_string())?;
            Vault::complete_initialization(&self.config.root).map_err(|error| error.to_string())?;
            Ok(metadata)
        })();
        lifecycle.disarm();
        match result {
            Ok(metadata) => Ok(metadata),
            Err(initialization_error) => match Vault::discard_initialization(&self.config.root) {
                Ok(()) => Err(initialization_error),
                Err(cleanup_error) => Err(format!(
                    "{initialization_error}; initialization rollback failed: {cleanup_error}"
                )),
            },
        }
    }

    fn open_and_serve(
        &self,
        metadata: &VaultMetadata,
        group: &UnlockGroup,
        password: &[u8],
    ) -> Result<(), String> {
        let lifecycle = crate::timing::result("desktop_runtime", "create_lifecycle", || {
            new_lifecycle().map_err(|error| error.to_string())
        })?;
        crate::timing::result("desktop_runtime", "arm_lifecycle", || {
            lifecycle.arm().map_err(|error| error.to_string())
        })?;
        let result = (|| {
            let credentials = if group.requires(UnlockFactorKind::Password) {
                UnlockCredentials::with_password(password)
            } else {
                UnlockCredentials::none()
            };
            let unsealed = crate::timing::result("desktop_runtime", "unseal_vault_keys", || {
                Vault::unseal_with_unlock_group(&self.config.root, group, credentials)
                    .map_err(|error| error.to_string())
            })?;
            crate::timing::mark_unlock("keys_unsealed", "ok");
            let now = crate::timing::result("desktop_runtime", "read_clock", unix_time)?;
            let service = Arc::new(crate::timing::result(
                "desktop_runtime",
                "open_vault_service",
                || {
                    VaultService::open(&self.config.root, unsealed, now, self.config.lease)
                        .map_err(|error| error.to_string())
                },
            )?);
            crate::timing::mark_unlock("service_open", "ok");
            // Native caller identities include the executable digest, so a
            // Desktop upgrade must refresh its first-party grants after the
            // user has successfully unsealed the vault.
            crate::timing::result("desktop_runtime", "authorize_first_party_clients", || {
                authorize_desktop(&service, now)
            })?;
            crate::timing::result("desktop_runtime", "publish_service", || {
                self.service
                    .lock()
                    .map_err(|_| "the desktop runtime lock is unavailable".to_owned())?
                    .replace(Arc::clone(&service));
                Ok::<_, String>(())
            })?;
            let idle_deadline = now.saturating_add(self.config.lease.idle_timeout.as_secs());
            let absolute_deadline =
                now.saturating_add(self.config.lease.maximum_lifetime.as_secs());
            let inventory = crate::timing::result("desktop_runtime", "load_inventory", || {
                load_vault_contents_from_service(&service)
            });
            let inventory_outcome = if inventory.is_ok() { "ok" } else { "error" };
            let (contents, contents_error) = match inventory {
                Ok(contents) => (contents, None),
                Err(error) => (VaultContents::default(), Some(error)),
            };
            crate::timing::mark_unlock("inventory_loaded", inventory_outcome);
            let _ = self.events.try_send(Snapshot::Unsealed {
                metadata: metadata.clone(),
                idle_deadline,
                absolute_deadline,
                owned: true,
                contents,
                contents_error,
                error: None,
            });
            crate::timing::mark_unlock("snapshot_queued", "ok");
            serve(&self.config, metadata, &service, &lifecycle).map_err(|error| error.to_string())
        })();
        lifecycle.disarm();
        result
    }
}

fn portable_entry(entry: &VaultEntryMetadata) -> bool {
    !matches!(
        entry.document_kind,
        DocumentKind::Authorization | DocumentKind::SecretSpecProviderCache
    )
}

fn is_personal_entry(entry: &VaultEntryMetadata) -> bool {
    entry.document_kind == DocumentKind::LocalKeyring
        && entry.partition == PERSONAL_SECRET_NAMESPACE
}

fn unique_personal_name(title: &str, occupied: &[String]) -> String {
    let mut suffix = 2_u64;
    loop {
        let candidate = format!("{title} ({suffix})");
        if !occupied.contains(&candidate) {
            return candidate;
        }
        suffix = suffix.saturating_add(1);
    }
}

fn load_vault_contents_from_service(service: &VaultService) -> Result<VaultContents, String> {
    let executable = crate::timing::result("desktop_inventory", "resolve_executable", || {
        std::env::current_exe().map_err(|error| error.to_string())
    })?;
    let caller = crate::timing::result("desktop_inventory", "identify_executable", || {
        current_executable_identity(&executable)
    })?;
    load_vault_contents(|action| {
        let request = VaultRequest::new(action).map_err(|error| error.to_string())?;
        service
            .handle(&caller, request, unix_time()?)
            .result
            .map_err(|error| error.message)
    })
}

fn load_vault_contents_from_client(client: &impl VaultClient) -> Result<VaultContents, String> {
    load_vault_contents(|action| {
        let request = VaultRequest::new(action).map_err(|error| error.to_string())?;
        client
            .request(&request)
            .map_err(|error| error.to_string())?
            .result
            .map_err(|error| error.message)
    })
}

fn load_vault_contents(
    mut request: impl FnMut(VaultAction) -> Result<VaultResponseBody, String>,
) -> Result<VaultContents, String> {
    let mut entries = Vec::new();
    let mut cursor = None;
    loop {
        let response = crate::timing::result("desktop_inventory", "list_entries_page", || {
            request(VaultAction::ListVaultEntries {
                cursor: cursor.clone(),
                limit: MAX_LIST_PAGE_SIZE,
            })
        })?;
        let VaultResponseBody::VaultEntries {
            entries: page,
            next_cursor,
        } = response
        else {
            return Err("vault returned an unexpected inventory response".to_owned());
        };
        entries.extend(page);
        if next_cursor.is_none() {
            break;
        }
        if next_cursor == cursor {
            return Err("vault returned a repeated inventory cursor".to_owned());
        }
        cursor = next_cursor;
    }

    let VaultResponseBody::Permissions { permissions, .. } =
        crate::timing::result("desktop_inventory", "list_permissions", || {
            request(VaultAction::ListPermissions)
        })?
    else {
        return Err("vault returned an unexpected permission-list response".to_owned());
    };
    Ok(VaultContents {
        entries,
        permissions,
        secret_service_error: {
            let started = std::time::Instant::now();
            let error = secret_service_error();
            crate::timing::record("desktop_inventory", "probe_secret_service", started, "ok");
            error
        },
    })
}

#[cfg(target_os = "linux")]
fn secret_service_error() -> Option<String> {
    use dbus::blocking::Connection;
    use dbus::blocking::stdintf::org_freedesktop_dbus::Properties as _;

    const BUS_NAME: &str = "org.freedesktop.secrets";
    const SERVICE_PATH: &str = "/org/freedesktop/secrets";
    const SERVICE_INTERFACE: &str = "org.freedesktop.Secret.Service";

    let connection = match Connection::new_session() {
        Ok(connection) => connection,
        Err(error) => {
            return Some(format!(
                "System keyring integration cannot connect to the session D-Bus: {error}. FactorSeal's vault is still available."
            ));
        }
    };
    let bus = connection.with_proxy(
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        Duration::from_secs(2),
    );
    let owner: Result<(bool,), dbus::Error> =
        bus.method_call("org.freedesktop.DBus", "NameHasOwner", (BUS_NAME,));
    match owner {
        Ok((false,)) => return None,
        Ok((true,)) => {}
        Err(error) => {
            return Some(format!(
                "System keyring integration could not inspect the session D-Bus: {error}. FactorSeal's vault is still available."
            ));
        }
    }

    let service = connection.with_proxy(BUS_NAME, SERVICE_PATH, Duration::from_secs(2));
    let collections: Result<Vec<dbus::Path<'static>>, dbus::Error> =
        service.get(SERVICE_INTERFACE, "Collections");
    match collections {
        Ok(collections) if factorseal_secret_service(&collections) => None,
        Ok(_) => Some(
            "System keyring integration is unavailable because another application owns org.freedesktop.secrets. FactorSeal's vault is still available. Disable the other Secret Service provider and restart FactorSeal."
                .to_owned(),
        ),
        Err(error) => Some(format!(
            "System keyring integration could not inspect the active Secret Service provider: {error}. FactorSeal's vault is still available."
        )),
    }
}

#[cfg(target_os = "linux")]
fn factorseal_secret_service(collections: &[dbus::Path<'_>]) -> bool {
    collections
        .iter()
        .any(|path| path == "/org/freedesktop/secrets/collection/factorseal")
}

#[cfg(not(target_os = "linux"))]
const fn secret_service_error() -> Option<String> {
    None
}

fn authorize_desktop(service: &VaultService, now: u64) -> Result<(), String> {
    let executable = crate::timing::result("desktop_authorization", "resolve_desktop", || {
        std::env::current_exe().map_err(|error| error.to_string())
    })?;
    crate::timing::result("desktop_authorization", "authorize_desktop", || {
        authorize_first_party(service, &executable, DESKTOP_CONTROL_NAMESPACE, now)
    })?;
    if let Some(cli) = crate::timing::result("desktop_authorization", "resolve_cli", || {
        cli_executable(&executable)
    })? {
        crate::timing::result("desktop_authorization", "authorize_cli", || {
            authorize_first_party(service, &cli, CLI_CONTROL_NAMESPACE, now)
        })?;
    }
    Ok(())
}

fn authorize_first_party(
    service: &VaultService,
    executable: &Path,
    control_namespace: &[u8],
    now: u64,
) -> Result<(), String> {
    let caller = crate::timing::result("first_party_grants", "identify_executable", || {
        current_executable_identity(executable)
    })?;
    crate::timing::result("first_party_grants", "authorize_projects", || {
        service
            .authorize_document_kind(
                &caller,
                DocumentKind::SecretSpecProject,
                DESKTOP_PROJECT_PERMISSIONS,
                None,
                now,
            )
            .map_err(|error| error.to_string())
    })?;
    crate::timing::result("first_party_grants", "authorize_control", || {
        service
            .authorize_namespace(
                &caller,
                control_namespace,
                [GrantPermission::Seal],
                None,
                now,
            )
            .map_err(|error| error.to_string())
    })?;
    crate::timing::result("first_party_grants", "authorize_personal_secrets", || {
        service
            .authorize_namespace(
                &caller,
                PERSONAL_SECRET_NAMESPACE,
                [
                    GrantPermission::List,
                    GrantPermission::Get,
                    GrantPermission::Put,
                    GrantPermission::Delete,
                ],
                None,
                now,
            )
            .map_err(|error| error.to_string())
    })?;
    crate::timing::result("first_party_grants", "authorize_permission_manager", || {
        service
            .authorize_permission_manager(&caller, now)
            .map_err(|error| error.to_string())
    })
}

fn cli_executable(desktop: &Path) -> Result<Option<PathBuf>, String> {
    if let Some(path) = std::env::var_os(CLI_EXECUTABLE_ENV) {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(format!("{CLI_EXECUTABLE_ENV} must be an absolute path"));
        }
        if !path.is_file() {
            return Err(format!(
                "{CLI_EXECUTABLE_ENV} does not name a regular file: {}",
                path.display()
            ));
        }
        return Ok(Some(path));
    }
    let name = if cfg!(windows) {
        "factorseal.exe"
    } else {
        "factorseal"
    };
    Ok(desktop
        .parent()
        .map(|parent| parent.join(name))
        .filter(|path| path.is_file()))
}

#[cfg(target_os = "linux")]
fn current_executable_identity(executable: &Path) -> Result<factorseal::CallerIdentity, String> {
    linux_caller_identity_for_executable(executable).map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn current_executable_identity(executable: &Path) -> Result<factorseal::CallerIdentity, String> {
    macos_caller_identity_for_executable(executable).map_err(|error| error.to_string())
}

#[cfg(target_os = "windows")]
fn current_executable_identity(executable: &Path) -> Result<factorseal::CallerIdentity, String> {
    windows_caller_identity_for_executable(executable).map_err(|error| error.to_string())
}

impl Drop for DesktopRuntime {
    fn drop(&mut self) {
        if let Ok(service) = self.service.get_mut()
            && let Some(service) = service
        {
            let _ = service.seal();
        }
    }
}

fn live_status(
    config: &RuntimeConfig,
    metadata: &VaultMetadata,
) -> Result<Option<(u64, u64)>, String> {
    let client = native_client(config, metadata);
    let request = VaultRequest::new(VaultAction::Status).map_err(|error| error.to_string())?;
    match client.request(&request) {
        Ok(response) => match response.result {
            Ok(VaultResponseBody::Status {
                installation_id,
                idle_deadline,
                absolute_deadline,
                ..
            }) if installation_id == metadata.installation_id().to_string() => {
                Ok(Some((idle_deadline, absolute_deadline)))
            }
            Err(error) if matches!(error.code, factorseal::VaultResponseErrorCode::Sealed) => {
                Ok(None)
            }
            Ok(_) | Err(_) => Err("another or incompatible service owns the endpoint".to_owned()),
        },
        Err(factorseal::VaultError::AgentUnreachable(_)) => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn native_client(config: &RuntimeConfig, _metadata: &VaultMetadata) -> NativeVaultClient {
    NativeVaultClient::new(
        config
            .socket
            .clone()
            .unwrap_or_else(|| config.root.join(DEFAULT_SOCKET)),
    )
}

#[cfg(target_os = "windows")]
fn native_client(config: &RuntimeConfig, metadata: &VaultMetadata) -> NativeVaultClient {
    config.socket.as_ref().map_or_else(
        || NativeVaultClient::for_installation(metadata.installation_id()),
        |path| NativeVaultClient::new(path.to_string_lossy().into_owned()),
    )
}

#[cfg(target_os = "linux")]
fn new_lifecycle() -> factorseal::VaultResult<NativeLifecycle> {
    NativeLifecycle::new()
}

#[cfg(target_os = "macos")]
fn new_lifecycle() -> factorseal::VaultResult<NativeLifecycle> {
    Ok(NativeLifecycle::new())
}

#[cfg(target_os = "windows")]
fn new_lifecycle() -> factorseal::VaultResult<NativeLifecycle> {
    NativeLifecycle::new()
}

#[cfg(target_os = "linux")]
fn serve(
    config: &RuntimeConfig,
    _metadata: &VaultMetadata,
    service: &Arc<VaultService>,
    lifecycle: &NativeLifecycle,
) -> factorseal::VaultResult<()> {
    let mut options = LinuxVaultOptions::new(
        config
            .socket
            .clone()
            .unwrap_or_else(|| config.root.join(DEFAULT_SOCKET)),
    );
    options.install_signal_handler = false;
    serve_linux_vault_with_lifecycle(service, &options, Some(lifecycle))
}

#[cfg(target_os = "macos")]
fn serve(
    config: &RuntimeConfig,
    _metadata: &VaultMetadata,
    service: &Arc<VaultService>,
    lifecycle: &NativeLifecycle,
) -> factorseal::VaultResult<()> {
    let mut options = MacosVaultOptions::new(
        config
            .socket
            .clone()
            .unwrap_or_else(|| config.root.join(DEFAULT_SOCKET)),
    );
    options.install_signal_handler = false;
    serve_macos_vault_with_lifecycle(service, &options, Some(lifecycle))
}

#[cfg(target_os = "windows")]
fn serve(
    config: &RuntimeConfig,
    metadata: &VaultMetadata,
    service: &Arc<VaultService>,
    lifecycle: &NativeLifecycle,
) -> factorseal::VaultResult<()> {
    let pipe = config.socket.as_ref().map_or_else(
        || default_windows_pipe_name(metadata.installation_id()),
        |path| path.to_string_lossy().into_owned(),
    );
    let mut options = WindowsVaultOptions::new(pipe);
    options.install_signal_handler = false;
    serve_windows_vault_with_lifecycle(service, &options, Some(lifecycle))
}

fn unix_time() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

pub(crate) fn default_root() -> Result<PathBuf, String> {
    directories::ProjectDirs::from("dev", "Factorseal", "Factorseal")
        .map(|directories| directories.data_local_dir().to_owned())
        .ok_or_else(|| "could not determine the platform user-data directory".to_owned())
}

pub(crate) fn lease_policy(
    idle_seconds: u64,
    maximum_seconds: u64,
) -> Result<UnsealLeasePolicy, String> {
    if idle_seconds == 0 || maximum_seconds == 0 || idle_seconds > maximum_seconds {
        return Err(
            "idle and maximum lease durations must be positive, and idle must not exceed maximum"
                .to_owned(),
        );
    }
    Ok(UnsealLeasePolicy {
        idle_timeout: Duration::from_secs(idle_seconds),
        maximum_lifetime: Duration::from_secs(maximum_seconds),
    })
}

pub(crate) fn explicit_or_default_root(root: Option<&Path>) -> Result<PathBuf, String> {
    root.map_or_else(default_root, |root| Ok(root.to_owned()))
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use factorseal::{
        DocumentKind, SecretAddress, SecretSpecAddress, VaultEntryMetadata, VaultResponseBody,
    };

    #[cfg(target_os = "linux")]
    use super::factorseal_secret_service;
    use super::load_vault_contents;

    #[cfg(target_os = "linux")]
    #[test]
    fn recognizes_factorseal_as_the_secret_service_provider() {
        let factorseal = dbus::Path::new("/org/freedesktop/secrets/collection/factorseal").unwrap();
        let other = dbus::Path::new("/org/freedesktop/secrets/collection/login").unwrap();

        assert!(factorseal_secret_service(&[factorseal]));
        assert!(!factorseal_secret_service(&[other]));
    }

    #[test]
    fn vault_contents_follow_every_inventory_page() {
        let first = SecretSpecAddress::convention("alpha", "default", "TOKEN").unwrap();
        let second = SecretSpecAddress::convention("beta", "production", "DATABASE_URL").unwrap();
        let first = VaultEntryMetadata {
            document_kind: DocumentKind::SecretSpecProject,
            partition: b"alpha".to_vec(),
            address: SecretAddress::secret_spec(first).unwrap(),
        };
        let second = VaultEntryMetadata {
            document_kind: DocumentKind::SecretSpecProject,
            partition: b"beta".to_vec(),
            address: SecretAddress::secret_spec(second).unwrap(),
        };
        let mut responses = VecDeque::from([
            VaultResponseBody::VaultEntries {
                entries: vec![first.clone()],
                next_cursor: Some("first-page".to_owned()),
            },
            VaultResponseBody::VaultEntries {
                entries: vec![second.clone()],
                next_cursor: None,
            },
            VaultResponseBody::Permissions {
                revision: 0,
                permissions: Vec::new(),
            },
        ]);

        let contents = load_vault_contents(|_| {
            responses
                .pop_front()
                .ok_or_else(|| "unexpected request".to_owned())
        })
        .unwrap();

        assert!(responses.is_empty());
        assert_eq!(contents.entries, vec![first, second]);
        assert!(contents.permissions.is_empty());
    }
}

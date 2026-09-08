use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use factorseal::security::LockedBytes;
use factorseal::{
    DocumentKind, MAX_LIST_PAGE_SIZE, NativeVaultClient, UnlockGroup, UnlockPolicy, Vault,
    VaultAction, VaultArchive, VaultClient, VaultEntryMetadata, VaultMetadata, VaultRequest,
    VaultResponseBody, WireSecret, WireSecretAddress, decrypt_vault_archive, encrypt_vault_archive,
};
use zeroize::Zeroizing;

use factorseal::transfer::{PersonalSecret, TransferFormat, export_manager};

#[derive(Clone, Copy)]
pub(crate) enum TransferKey<'a> {
    Passphrase(&'a [u8]),
    HybridFile(&'a Path),
}

impl TransferKey<'_> {
    fn encrypt_cxf(&self, payload: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        use factorseal::transfer::cxf;
        match self {
            Self::Passphrase(passphrase) => {
                factorseal::security::validate_new_password(passphrase)?;
                cxf::encrypt(payload, passphrase)
            }
            Self::HybridFile(path) => cxf::read_recipient_file(path)
                .and_then(|recipient| cxf::encrypt_to_recipient(payload, &recipient)),
        }
        .map_err(|error| error.to_string())
    }

    fn decrypt_cxf(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        use factorseal::transfer::cxf;
        match self {
            Self::Passphrase(passphrase) => cxf::decrypt(bytes, passphrase),
            Self::HybridFile(path) => cxf::read_identity_file(path)
                .and_then(|identity| cxf::decrypt_with_hybrid_identity(bytes, &identity)),
        }
        .map_err(|error| error.to_string())
    }
}

const METADATA_FILE: &str = "factorseal.json";
pub(crate) use factorseal::personal::PERSONAL_SECRET_NAMESPACE;
const CLI_EXECUTABLE_ENV: &str = "FACTORSEAL_CLI_EXECUTABLE";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const DEFAULT_SOCKET: &str = "factorseal.sock";

#[derive(Clone, Copy, Debug)]
pub(crate) struct LeasePolicy {
    pub(crate) idle_timeout: Duration,
    pub(crate) maximum_lifetime: Duration,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeConfig {
    pub(crate) root: PathBuf,
    pub(crate) socket: Option<PathBuf>,
    pub(crate) lease: LeasePolicy,
    /// This Desktop serves `org.freedesktop.secrets` and needs the adapter
    /// grant from every worker it starts.
    pub(crate) secret_service: bool,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct VaultContents {
    pub(crate) entries: Vec<VaultEntryMetadata>,
    pub(crate) permissions: Vec<factorseal::Permission>,
    pub(crate) permissions_loading: bool,
    pub(crate) permissions_error: Option<String>,
    pub(crate) secret_service_error: Option<String>,
}

impl VaultContents {
    pub(crate) fn complete_permissions(
        &mut self,
        result: Result<Vec<factorseal::Permission>, String>,
    ) {
        if !self.permissions_loading {
            return;
        }
        self.permissions_loading = false;
        self.permissions_error = None;
        match result {
            Ok(permissions) => self.permissions = permissions,
            Err(error) => self.permissions_error = Some(error),
        }
    }
}

pub(crate) use factorseal::transfer::import_plan::{
    ImportSummary as TransferSummary, PreparedImport,
};

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
    next_lease: Mutex<LeasePolicy>,
    events: smol::channel::Sender<Snapshot>,
    lifeline: Mutex<Option<std::process::ChildStdin>>,
    unlock_in_progress: AtomicBool,
    sync_output: Mutex<Option<std::process::ChildStdout>>,
    sync_io: Mutex<()>,
    sync_manager: Mutex<Option<Arc<factorseal::desktop_worker::sync::network::Manager>>>,
}

impl DesktopRuntime {
    pub(crate) fn new(config: RuntimeConfig) -> (Arc<Self>, smol::channel::Receiver<Snapshot>) {
        let (events, receiver) = smol::channel::bounded(16);
        (
            Arc::new(Self {
                next_lease: Mutex::new(config.lease),
                config,
                events,
                lifeline: Mutex::new(None),
                unlock_in_progress: AtomicBool::new(false),
                sync_output: Mutex::new(None),
                sync_io: Mutex::new(()),
                sync_manager: Mutex::new(None),
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
                    owned: self.lifeline.lock().is_ok_and(|pipe| pipe.is_some()),
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

    pub(crate) fn set_next_lease(&self, lease: LeasePolicy) {
        if let Ok(mut next) = self.next_lease.lock() {
            *next = lease;
        }
    }

    pub(crate) fn unlock(
        self: &Arc<Self>,
        metadata: VaultMetadata,
        group: UnlockGroup,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<(), &'static str> {
        let password =
            LockedBytes::from_zeroizing(password).map_err(|_| "could not lock password memory")?;
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
                runtime.run_unsealed(metadata, group, password);
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
        let password =
            LockedBytes::from_zeroizing(password).map_err(|_| "could not lock password memory")?;
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
            .spawn(move || runtime.run_initialization(policy, password))
            .is_err()
        {
            self.unlock_in_progress.store(false, Ordering::Release);
            return Err("could not start the initialization worker");
        }
        Ok(())
    }

    /// Native socket client for the Desktop's own vault access, such as the
    /// Secret Service adapter it hosts.
    #[cfg(target_os = "linux")]
    pub(crate) fn vault_client(&self) -> NativeVaultClient {
        NativeVaultClient::new(
            self.config
                .socket
                .clone()
                .unwrap_or_else(|| self.config.root.join(DEFAULT_SOCKET)),
        )
    }

    pub(crate) fn seal(&self) -> Result<(), String> {
        let pipe = self
            .lifeline
            .lock()
            .map_err(|_| "desktop worker lock unavailable".to_owned())?
            .take();
        if pipe.is_none() {
            return Err("this Desktop instance does not own the running agent".to_owned());
        }
        drop(pipe);
        Ok(())
    }

    pub(crate) fn read_personal_item(
        &self,
        metadata: &VaultMetadata,
        entry: &VaultEntryMetadata,
    ) -> Result<PersonalSecret, String> {
        if !is_personal_entry(entry) {
            return Err("This is not a personal item.".into());
        }
        let request = VaultRequest::new(VaultAction::ExportVaultEntry {
            entry: entry.clone(),
        })
        .map_err(|error| error.to_string())?;
        match self.request_live(metadata, &request)? {
            VaultResponseBody::VaultEntrySecret { value, .. } => {
                PersonalSecret::decode_current(value.expose()).map_err(|error| error.to_string())
            }
            _ => Err("Could not read the personal item.".into()),
        }
    }

    pub(crate) fn put_personal_secret(
        &self,
        secret: &PersonalSecret,
    ) -> Result<VaultContents, String> {
        let metadata = Vault::inspect(&self.config.root).map_err(|error| error.to_string())?;
        let encoded = secret.encode().map_err(|error| error.to_string())?;
        let request = VaultRequest::new(VaultAction::Put {
            namespace: PERSONAL_SECRET_NAMESPACE.to_vec(),
            address: WireSecretAddress::new(secret.id.clone(), None),
            value: WireSecret::new(encoded.to_vec()).map_err(|e| e.to_string())?,
            evict_at: None,
        })
        .map_err(|error| error.to_string())?;
        match self.request_live(&metadata, &request)? {
            VaultResponseBody::Stored => self.load_live_contents(&metadata),
            _ => Err("vault returned an unexpected personal-secret response".to_owned()),
        }
    }

    pub(crate) fn export_native_archive(
        &self,
        metadata: &VaultMetadata,
        passphrase: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let archived =
            factorseal::read_vault_export(&native_client(&self.config, metadata), |_| true)
                .map_err(|error| error.to_string())?;
        let archive = VaultArchive::new(unix_time()?, archived);
        encrypt_vault_archive(&archive, passphrase).map_err(|error| error.to_string())
    }

    pub(crate) fn prepare_import(
        bytes: &[u8],
        format: TransferFormat,
        key: TransferKey<'_>,
    ) -> Result<PreparedImport, String> {
        if format.is_native() {
            let TransferKey::Passphrase(passphrase) = key else {
                return Err("Native archives require a passphrase".into());
            };
            let archive =
                decrypt_vault_archive(bytes, passphrase).map_err(|error| error.to_string())?;
            return PreparedImport::archive(archive, unix_time()?)
                .map_err(|error| error.to_string());
        }
        let decrypted;
        let bytes = if format == TransferFormat::CxfAge {
            decrypted = key.decrypt_cxf(bytes)?;
            &decrypted
        } else {
            bytes
        };
        PreparedImport::manager(format, bytes).map_err(|error| error.to_string())
    }

    pub(crate) fn export_password_manager(
        &self,
        metadata: &VaultMetadata,
        format: TransferFormat,
        key: TransferKey<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let secrets = self.read_personal_secrets(metadata)?;
        let payload = export_manager(format, &secrets).map_err(|error| error.to_string())?;
        if format == TransferFormat::CxfAge {
            key.encrypt_cxf(&payload)
        } else {
            Ok(payload)
        }
    }

    #[cfg(feature = "apple-credential-exchange")]
    pub(crate) fn export_system_credentials(
        &self,
        metadata: &VaultMetadata,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let secrets = self.read_personal_secrets(metadata)?;
        factorseal::transfer::cxf::export_json(&secrets).map_err(|error| error.to_string())
    }

    pub(crate) fn commit_import(
        &self,
        metadata: &VaultMetadata,
        prepared: PreparedImport,
        replace_existing: bool,
    ) -> Result<(TransferSummary, VaultContents), String> {
        let summary = prepared
            .commit(&native_client(&self.config, metadata), replace_existing)
            .map_err(|error| error.to_string())?;
        let contents = self.load_live_contents(metadata).map_err(|error| {
            format!(
                "Import completed for {} items, but refreshing the vault failed: {error}",
                summary.processed()
            )
        })?;
        Ok((summary, contents))
    }

    fn read_personal_secrets(
        &self,
        metadata: &VaultMetadata,
    ) -> Result<Vec<PersonalSecret>, String> {
        factorseal::read_vault_export(&native_client(&self.config, metadata), is_personal_entry)
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|entry| {
                let title = entry
                    .metadata
                    .address
                    .as_local()
                    .ok_or("invalid personal-secret address")?
                    .0;
                let value = entry.value;
                PersonalSecret::decode(title, value.expose()).map_err(|error| error.to_string())
            })
            .collect()
    }

    fn load_live_contents(&self, metadata: &VaultMetadata) -> Result<VaultContents, String> {
        load_vault_contents_from_client(&native_client(&self.config, metadata))
    }

    pub(crate) fn load_permissions(
        &self,
        metadata: &VaultMetadata,
    ) -> Result<Vec<factorseal::Permission>, String> {
        load_permissions(|action| {
            let request = VaultRequest::new(action).map_err(|error| error.to_string())?;
            self.request_live(metadata, &request)
        })
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn approve_permissions(
        &self,
        metadata: &VaultMetadata,
        permissions: &[factorseal::Permission],
        group: factorseal::UnlockGroup,
        password: Zeroizing<Vec<u8>>,
        duration: Option<u64>,
    ) -> Result<(), String> {
        let requests = permissions
            .iter()
            .map(|permission| {
                let factorseal::PermissionState::Pending { challenge, .. } = permission.state
                else {
                    return Err("permission is no longer pending".to_owned());
                };
                Ok((permission.id.clone(), challenge, duration))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let password = LockedBytes::from_zeroizing(password).map_err(|error| error.to_string())?;
        let mut worker = self.spawn_worker(
            factorseal::desktop_worker::Operation::SignPermissions { group, requests },
            password,
        )?;
        let signatures = factorseal::desktop_worker::receive::<Result<Vec<Vec<u8>>, String>>(
            worker
                .child
                .stdout
                .as_mut()
                .ok_or("signing worker output unavailable")?,
        )
        .map_err(|error| error.to_string())??;
        worker.wait()?;
        if signatures.len() != permissions.len() {
            return Err("invalid signing response".to_owned());
        }
        for (permission, signature) in permissions.iter().zip(signatures) {
            self.request_live(
                metadata,
                &VaultRequest::new(factorseal::VaultAction::ApprovePermission {
                    id: permission.id.clone(),
                    signature,
                    duration_seconds: duration,
                })
                .map_err(|error| error.to_string())?,
            )?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn deny_permission(
        &self,
        metadata: &VaultMetadata,
        id: String,
    ) -> Result<(), String> {
        self.request_live(
            metadata,
            &VaultRequest::new(factorseal::VaultAction::DenyPermission { id })
                .map_err(|error| error.to_string())?,
        )
        .map(|_| ())
    }

    pub(crate) fn wait_permissions(
        &self,
        metadata: &VaultMetadata,
        revision: Option<u64>,
    ) -> Result<(u64, Vec<factorseal::Permission>), String> {
        factorseal::read_permission_pages(
            |action| {
                let request = VaultRequest::new(action)?;
                self.request_live(metadata, &request)
                    .map_err(factorseal::VaultError::Protocol)
            },
            revision,
        )
        .map_err(|error| error.to_string())
    }

    pub(crate) fn approve_permission(
        &self,
        metadata: &VaultMetadata,
        permission: &factorseal::Permission,
        duration_seconds: u64,
        group: UnlockGroup,
        password: Zeroizing<Vec<u8>>,
    ) -> Result<(), String> {
        if !self.load_permissions(metadata)?.contains(permission) {
            return Err("Permission changed or expired. Review the current request.".into());
        }
        let factorseal::PermissionState::Pending { challenge, .. } = permission.state else {
            return Err("Permission is already granted.".into());
        };
        let password = LockedBytes::from_zeroizing(password).map_err(|error| error.to_string())?;
        let mut worker = self.spawn_worker(
            factorseal::desktop_worker::Operation::SignPermission {
                id: permission.id.clone(),
                challenge,
                duration_seconds: Some(duration_seconds),
                group,
            },
            password,
        )?;
        let signature: Result<Vec<u8>, String> = factorseal::desktop_worker::receive(
            worker
                .child
                .stdout
                .as_mut()
                .ok_or("worker output unavailable")?,
        )
        .map_err(|error| error.to_string())?;
        let signature = signature?;
        worker.wait()?;
        self.change_permission(
            metadata,
            VaultAction::ApprovePermission {
                id: permission.id.clone(),
                signature,
                duration_seconds: Some(duration_seconds),
            },
            factorseal::PermissionChange::Granted,
        )
    }

    pub(crate) fn change_permission(
        &self,
        metadata: &VaultMetadata,
        action: VaultAction,
        expected: factorseal::PermissionChange,
    ) -> Result<(), String> {
        let request = VaultRequest::new(action).map_err(|error| error.to_string())?;
        match self.request_live(metadata, &request)? {
            VaultResponseBody::PermissionChanged { status } if status == expected => Ok(()),
            _ => Err("Unexpected permission response.".into()),
        }
    }

    fn request_live(
        &self,
        metadata: &VaultMetadata,
        request: &VaultRequest,
    ) -> Result<VaultResponseBody, String> {
        native_client(&self.config, metadata)
            .request(request)
            .map_err(|error| error.to_string())?
            .result
            .map_err(|error| error.message)
    }

    pub(crate) fn start_seal(self: &Arc<Self>, _metadata: VaultMetadata) -> Result<(), String> {
        // The supervisor publishes Sealed only after the worker has exited.
        self.seal()
    }

    fn run_unsealed(
        self: Arc<Self>,
        metadata: VaultMetadata,
        group: UnlockGroup,
        password: LockedBytes,
    ) {
        let result = self.supervise_worker(&metadata, group, password);
        factorseal::diagnostics::event(
            "desktop",
            "supervise_worker",
            if result.is_ok() { "ok" } else { "error" },
        );
        if let Ok(mut pipe) = self.lifeline.lock() {
            pipe.take();
        }
        self.unlock_in_progress.store(false, Ordering::Release);
        let _ = self.events.try_send(Snapshot::Sealed {
            metadata,
            error: result.err(),
        });
    }

    fn run_initialization(self: Arc<Self>, policy: UnlockPolicy, password: LockedBytes) {
        factorseal::diagnostics::event("desktop", "initialize_vault", "start");
        let result = (|| {
            let mut worker = self.spawn_worker(
                factorseal::desktop_worker::Operation::Initialize { policy },
                password,
            )?;
            worker.read_ready()?;
            worker.wait()?;
            Vault::inspect(&self.config.root).map_err(|error| error.to_string())
        })();
        self.unlock_in_progress.store(false, Ordering::Release);
        factorseal::diagnostics::event(
            "desktop",
            "initialize_vault",
            if result.is_ok() { "ok" } else { "error" },
        );
        let snapshot = match result {
            Ok(metadata) => Snapshot::Sealed {
                metadata,
                error: None,
            },
            Err(error) => Snapshot::Error(error),
        };
        let _ = self.events.try_send(snapshot);
    }

    fn spawn_worker(
        &self,
        operation: factorseal::desktop_worker::Operation,
        password: LockedBytes,
    ) -> Result<Worker, String> {
        use std::process::{Command, Stdio};
        let desktop = std::env::current_exe().map_err(|e| e.to_string())?;
        let cli = cli_executable(&desktop)?.ok_or_else(|| "Factorseal CLI must be installed beside Desktop; set FACTORSEAL_CLI_EXECUTABLE to its absolute path".to_owned())?;
        let mut command = Command::new(cli);
        command.arg("--root").arg(&self.config.root);
        if let Some(socket) = &self.config.socket {
            command.arg("--socket").arg(socket);
        }
        command
            .arg("desktop-worker")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let child = command
            .spawn()
            .map_err(|e| format!("could not start vault worker: {e}"))?;
        factorseal::diagnostics::event("desktop", "spawn_worker", "ok");
        let mut worker = Worker {
            child,
            exit_reported: false,
        };
        let signing = matches!(
            operation,
            factorseal::desktop_worker::Operation::SignPermission { .. }
                | factorseal::desktop_worker::Operation::SignPermissions { .. }
        );
        let bootstrap = factorseal::desktop_worker::Bootstrap {
            desktop_executable: desktop,
            operation,
            password: WireSecret::from_locked(password),
            hosts_secret_service: !signing && self.config.secret_service,
            sync_control: !signing,
        };
        factorseal::desktop_worker::send(
            worker
                .child
                .stdin
                .as_mut()
                .ok_or("worker input unavailable")?,
            &bootstrap,
        )
        .map_err(|e| e.to_string())?;
        drop(bootstrap);
        Ok(worker)
    }

    fn unlock_operation(
        &self,
        group: UnlockGroup,
    ) -> Result<factorseal::desktop_worker::Operation, String> {
        let lease = *self
            .next_lease
            .lock()
            .map_err(|_| "desktop lease lock is unavailable".to_owned())?;
        Ok(factorseal::desktop_worker::Operation::Unlock {
            group,
            idle_seconds: lease.idle_timeout.as_secs(),
            maximum_seconds: lease.maximum_lifetime.as_secs(),
        })
    }

    fn supervise_worker(
        &self,
        metadata: &VaultMetadata,
        group: UnlockGroup,
        password: LockedBytes,
    ) -> Result<(), String> {
        let mut worker = crate::timing::result("desktop_startup", "spawn_worker", || {
            self.spawn_worker(self.unlock_operation(group)?, password)
        })?;
        crate::timing::result("desktop_startup", "wait_worker_ready", || {
            worker.read_ready()
        })?;
        let (idle_deadline, absolute_deadline) =
            crate::timing::result("desktop_startup", "wait_service_ready", || {
                let deadline = std::time::Instant::now() + Duration::from_secs(10);
                loop {
                    if let Some(status) = worker.child.try_wait().map_err(|e| e.to_string())? {
                        worker.record_exit(status);
                        return Err(format!("vault worker exited before serving: {status}"));
                    }
                    if let Some(deadlines) =
                        crate::timing::result("desktop_startup", "probe_live_status", || {
                            live_status(&self.config, metadata)
                        })?
                    {
                        return Ok(deadlines);
                    }
                    if std::time::Instant::now() >= deadline {
                        return Err("vault worker did not become ready".to_owned());
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
            })?;
        let control_install = self
            .sync_io
            .lock()
            .map_err(|_| "sync control lock unavailable")?;
        self.lifeline
            .lock()
            .map_err(|_| "desktop worker lock unavailable".to_owned())?
            .replace(
                worker
                    .child
                    .stdin
                    .take()
                    .ok_or("worker input unavailable")?,
            );
        self.sync_output
            .lock()
            .map_err(|_| "worker output lock unavailable")?
            .replace(
                worker
                    .child
                    .stdout
                    .take()
                    .ok_or("worker output unavailable")?,
            );
        drop(control_install);
        // Publish the inventory before requesting permissions. The UI starts
        // that request once it has applied this first unlocked snapshot.
        let client = native_client(&self.config, metadata);
        let (contents, contents_error) =
            match load_vault_entries(|action| request_contents(&client, action)) {
                Ok(contents) => (contents, None),
                Err(error) => (
                    VaultContents {
                        permissions_loading: true,
                        ..VaultContents::default()
                    },
                    Some(error),
                ),
            };
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
        worker.wait()
    }
}

/// On every error, terminate and reap the child rather than leaving an orphan.
struct Worker {
    child: std::process::Child,
    exit_reported: bool,
}
impl Worker {
    fn record_exit(&mut self, status: std::process::ExitStatus) {
        if !self.exit_reported {
            factorseal::diagnostics::child_exit(self.child.id(), status);
            self.exit_reported = true;
        }
    }

    fn read_ready(&mut self) -> Result<(), String> {
        factorseal::desktop_worker::receive::<Result<(), String>>(
            self.child
                .stdout
                .as_mut()
                .ok_or("worker output unavailable")?,
        )
        .map_err(|e| format!("vault worker startup failed: {e}"))?
    }
    fn wait(&mut self) -> Result<(), String> {
        let status = self.child.wait().map_err(|e| e.to_string())?;
        self.record_exit(status);
        if status.success() {
            Ok(())
        } else {
            Err(format!("vault worker exited: {status}"))
        }
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Ok(Some(status)) = self.child.try_wait() {
            self.record_exit(status);
            return;
        }
        let _ = self.child.kill();
        if let Ok(status) = self.child.wait() {
            // Reap the key owner before any diagnostic disk I/O.
            factorseal::diagnostics::event("worker", "supervisor_cleanup", "terminate");
            self.record_exit(status);
        }
    }
}

fn is_personal_entry(entry: &VaultEntryMetadata) -> bool {
    entry.document_kind == DocumentKind::LocalKeyring
        && entry.partition == PERSONAL_SECRET_NAMESPACE
}

fn load_vault_contents_from_client(client: &impl VaultClient) -> Result<VaultContents, String> {
    load_vault_contents(|action| request_contents(client, action))
}

fn request_contents(
    client: &impl VaultClient,
    action: VaultAction,
) -> Result<VaultResponseBody, String> {
    let request = VaultRequest::new(action).map_err(|error| error.to_string())?;
    client
        .request(&request)
        .map_err(|error| error.to_string())?
        .result
        .map_err(|error| error.message)
}

fn load_vault_contents(
    mut request: impl FnMut(VaultAction) -> Result<VaultResponseBody, String>,
) -> Result<VaultContents, String> {
    let mut contents = load_vault_entries(&mut request)?;
    contents.complete_permissions(Ok(load_permissions(request)?));
    Ok(contents)
}

fn load_vault_entries(
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

    Ok(VaultContents {
        entries,
        permissions_loading: true,
        secret_service_error: {
            let started = std::time::Instant::now();
            let error = secret_service_error();
            crate::timing::record("desktop_inventory", "probe_secret_service", started, "ok");
            error
        },
        ..VaultContents::default()
    })
}

fn load_permissions(
    mut request: impl FnMut(VaultAction) -> Result<VaultResponseBody, String>,
) -> Result<Vec<factorseal::Permission>, String> {
    factorseal::read_permission_pages(
        |action| request(action).map_err(factorseal::VaultError::Protocol),
        None,
    )
    .map(|(_, permissions)| permissions)
    .map_err(|error| error.to_string())
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

impl Drop for DesktopRuntime {
    fn drop(&mut self) {
        if let Ok(pipe) = self.lifeline.get_mut() {
            pipe.take();
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

pub(crate) fn lease_policy(idle_seconds: u64, maximum_seconds: u64) -> Result<LeasePolicy, String> {
    if idle_seconds == 0 || maximum_seconds == 0 || idle_seconds > maximum_seconds {
        return Err(
            "idle and maximum lease durations must be positive, and idle must not exceed maximum"
                .to_owned(),
        );
    }
    Ok(LeasePolicy {
        idle_timeout: Duration::from_secs(idle_seconds),
        maximum_lifetime: Duration::from_secs(maximum_seconds),
    })
}

pub(crate) fn explicit_or_default_root(root: Option<&Path>) -> Result<PathBuf, String> {
    root.map_or_else(default_root, |root| Ok(root.to_owned()))
}

impl DesktopRuntime {
    pub(crate) fn sync_view(
        self: &Arc<Self>,
    ) -> Result<factorseal::desktop_worker::sync::network::View, String> {
        if !self
            .config
            .root
            .join("personal-sync/transport.key")
            .is_file()
            && !self
                .config
                .root
                .join("personal-sync/membership.json")
                .is_file()
        {
            return Ok(factorseal::desktop_worker::sync::network::View::default());
        }
        self.sync_manager().map(|manager| manager.view())
    }
    pub(crate) fn sync_manager(
        self: &Arc<Self>,
    ) -> Result<Arc<factorseal::desktop_worker::sync::network::Manager>, String> {
        let mut manager = self
            .sync_manager
            .lock()
            .map_err(|_| "sync lock unavailable")?;
        if let Some(manager) = &*manager {
            return Ok(Arc::clone(manager));
        }
        if !self.config.root.join(METADATA_FILE).is_file() {
            return Err("Initialize your vault first".into());
        }
        let weak = Arc::downgrade(self);
        let host = Arc::new(move |command| {
            let runtime = weak.upgrade().ok_or("Desktop is closing")?;
            runtime.sync_command(&command)
        });
        let created = Arc::new(factorseal::desktop_worker::sync::network::Manager::open(
            &self.config.root.join("personal-sync"),
            host,
        )?);
        *manager = Some(Arc::clone(&created));
        Ok(created)
    }
    fn sync_command(
        &self,
        command: &factorseal::desktop_worker::sync::Command,
    ) -> Result<factorseal::desktop_worker::sync::Reply, String> {
        let _guard = self
            .sync_io
            .lock()
            .map_err(|_| "sync control lock unavailable")?;
        {
            let mut pipe = self
                .lifeline
                .lock()
                .map_err(|_| "worker lock unavailable")?;
            let input = pipe
                .as_mut()
                .ok_or("Unlock the vault in this Desktop to manage devices")?;
            factorseal::desktop_worker::sync::send(input, command)
                .map_err(|error| error.to_string())?;
        }
        let mut output = self
            .sync_output
            .lock()
            .map_err(|_| "worker output lock unavailable")?;
        factorseal::desktop_worker::sync::receive::<Result<_, String>>(
            output.as_mut().ok_or("Worker output unavailable")?,
        )
        .map_err(|error| error.to_string())?
    }
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

    #[test]
    fn lease_changes_preserve_the_captured_unlock_policy() {
        let directory = tempfile::tempdir().unwrap();
        let (runtime, _) = super::DesktopRuntime::new(super::RuntimeConfig {
            root: directory.path().to_path_buf(),
            socket: None,
            lease: super::lease_policy(300, 28_800).unwrap(),
            secret_service: false,
        });
        let group = factorseal::UnlockGroup::new([factorseal::UnlockFactorKind::Password]).unwrap();
        let captured = runtime.unlock_operation(group.clone()).unwrap();
        runtime.set_next_lease(super::lease_policy(60, 3600).unwrap());
        let next = runtime.unlock_operation(group.clone()).unwrap();
        for (operation, expected_idle, expected_maximum) in
            [(captured, 300, 28_800), (next, 60, 3600)]
        {
            let factorseal::desktop_worker::Operation::Unlock {
                group: worker_group,
                idle_seconds,
                maximum_seconds,
            } = operation
            else {
                panic!("expected an unlock operation");
            };
            assert_eq!(worker_group, group);
            assert_eq!(idle_seconds, expected_idle);
            assert_eq!(maximum_seconds, expected_maximum);
        }
    }

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
            display_name: None,
            display_type: None,
            updated_at: None,
            document_kind: DocumentKind::SecretSpecProject,
            partition: b"alpha".to_vec(),
            address: SecretAddress::secret_spec(first).unwrap(),
        };
        let second = VaultEntryMetadata {
            display_name: None,
            display_type: None,
            updated_at: None,
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
                next_cursor: None,
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
        assert!(!contents.permissions_loading);
    }

    #[test]
    fn initial_inventory_does_not_wait_for_permissions() {
        let entry = VaultEntryMetadata {
            display_name: None,
            display_type: None,
            updated_at: None,
            document_kind: DocumentKind::SecretSpecProject,
            partition: b"project".to_vec(),
            address: SecretAddress::secret_spec(
                SecretSpecAddress::convention("project", "default", "TOKEN").unwrap(),
            )
            .unwrap(),
        };
        let mut contents = super::load_vault_entries(|action| {
            assert!(matches!(
                action,
                factorseal::VaultAction::ListVaultEntries { .. }
            ));
            Ok(VaultResponseBody::VaultEntries {
                entries: vec![entry.clone()],
                next_cursor: None,
            })
        })
        .unwrap();
        assert_eq!(contents.entries, vec![entry.clone()]);
        assert!(contents.permissions_loading);
        assert!(contents.permissions.is_empty());

        // An unsuccessful follow-up must leave the visible inventory intact.
        contents.complete_permissions(Err("permission request failed".to_owned()));
        assert_eq!(contents.entries, vec![entry]);
        assert!(!contents.permissions_loading);
        assert_eq!(
            contents.permissions_error.as_deref(),
            Some("permission request failed")
        );
    }

    #[test]
    fn deferred_permissions_do_not_replace_already_refreshed_contents() {
        let mut contents = super::VaultContents {
            permissions_loading: true,
            ..super::VaultContents::default()
        };
        contents.complete_permissions(Ok(Vec::new()));
        assert!(!contents.permissions_loading);
        contents.complete_permissions(Err("stale response".to_owned()));
        assert!(contents.permissions_error.is_none());
    }
}

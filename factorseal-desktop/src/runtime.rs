use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use factorseal::{
    DocumentKind, GrantPermission, NativeVaultClient, UnlockCredentials, UnlockFactorKind,
    UnlockGroup, UnlockPolicy, UnsealLeasePolicy, Vault, VaultAction, VaultClient as _,
    VaultCryptoProfile, VaultMetadata, VaultRequest, VaultResponseBody, VaultService,
};
use zeroize::Zeroizing;

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
            Ok(Some((idle_deadline, absolute_deadline))) => Snapshot::Unsealed {
                metadata,
                idle_deadline,
                absolute_deadline,
                owned: false,
                error: None,
            },
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
        let runtime = Arc::clone(self);
        let event_metadata = metadata.clone();
        let event_group = group.clone();
        let _ = self.events.try_send(Snapshot::Unlocking {
            metadata: event_metadata,
            group: event_group,
        });
        if std::thread::Builder::new()
            .name("factorseal-desktop-agent".to_owned())
            .spawn(move || runtime.run_unsealed(metadata, &group, &password))
            .is_err()
        {
            self.unlock_in_progress.store(false, Ordering::Release);
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
        let lifecycle = new_lifecycle().map_err(|error| error.to_string())?;
        lifecycle.arm().map_err(|error| error.to_string())?;
        let result = (|| {
            let credentials = if group.requires(UnlockFactorKind::Password) {
                UnlockCredentials::with_password(password)
            } else {
                UnlockCredentials::none()
            };
            let unsealed = Vault::unseal_with_unlock_group(&self.config.root, group, credentials)
                .map_err(|error| error.to_string())?;
            let now = unix_time()?;
            let service = Arc::new(
                VaultService::open(&self.config.root, unsealed, now, self.config.lease)
                    .map_err(|error| error.to_string())?,
            );
            self.service
                .lock()
                .map_err(|_| "the desktop runtime lock is unavailable".to_owned())?
                .replace(Arc::clone(&service));
            let idle_deadline = now.saturating_add(self.config.lease.idle_timeout.as_secs());
            let absolute_deadline =
                now.saturating_add(self.config.lease.maximum_lifetime.as_secs());
            let _ = self.events.try_send(Snapshot::Unsealed {
                metadata: metadata.clone(),
                idle_deadline,
                absolute_deadline,
                owned: true,
                error: None,
            });
            serve(&self.config, metadata, &service, &lifecycle).map_err(|error| error.to_string())
        })();
        lifecycle.disarm();
        result
    }
}

fn authorize_desktop(service: &VaultService, now: u64) -> Result<(), String> {
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    authorize_first_party(service, &executable, DESKTOP_CONTROL_NAMESPACE, now)?;
    if let Some(cli) = cli_executable(&executable)? {
        authorize_first_party(service, &cli, CLI_CONTROL_NAMESPACE, now)?;
    }
    Ok(())
}

fn authorize_first_party(
    service: &VaultService,
    executable: &Path,
    control_namespace: &[u8],
    now: u64,
) -> Result<(), String> {
    let caller = current_executable_identity(executable)?;
    service
        .authorize_document_kind(
            &caller,
            DocumentKind::SecretSpecProject,
            DESKTOP_PROJECT_PERMISSIONS,
            None,
            now,
        )
        .map_err(|error| error.to_string())?;
    service
        .authorize_namespace(
            &caller,
            control_namespace,
            [GrantPermission::Seal],
            None,
            now,
        )
        .map_err(|error| error.to_string())?;
    service
        .authorize_permission_manager(&caller, now)
        .map_err(|error| error.to_string())
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

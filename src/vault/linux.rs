use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use dbus::Path as DbusPath;
use dbus::arg::OwnedFd;
use dbus::blocking::Connection;
use dbus::message::MatchRule;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::getuid;

use super::transport::unix_socket::{SocketGuard, prepare_socket_path, validate_socket_options};
use super::transport::{
    IPC_FRAME_IO_TIMEOUT, IoBudget, hash_file, hash_open_file, path_io_error, read_frame,
    unix_time, write_frame,
};
use super::{
    CallerIdentity, CallerIdentityCache, CallerPlatform, VaultError, VaultRequest, VaultResult,
    VaultService,
};
#[cfg(all(test, feature = "hardware"))]
use super::{LinuxVaultClient, VaultClient};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const LIFECYCLE_DBUS_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_ID_ENVIRONMENT: [&str; 2] = ["FACTORSEAL_SESSION_ID", "XDG_SESSION_ID"];

/// Linux per-user socket configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxVaultOptions {
    pub socket_path: PathBuf,
    pub poll_interval: Duration,
    /// Install SIGINT/SIGTERM handlers. Disable only when embedding the server
    /// in a process that owns signal handling itself.
    pub install_signal_handler: bool,
    /// Require systemd-logind sleep, shutdown, and session-lock monitoring.
    /// Disable only when an embedding process supplies equivalent hooks.
    pub install_lifecycle_monitor: bool,
}

impl LinuxVaultOptions {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            install_signal_handler: true,
            install_lifecycle_monitor: true,
        }
    }
}

/// Serve the shared vault protocol through a same-user Unix socket.
///
/// Caller identity comes from `SO_PEERCRED` and `/proc/<pid>/exe`; no identity
/// field from the request is trusted. This function blocks until explicit
/// lock, lease expiry, session lock, suspend, shutdown, SIGINT, or SIGTERM.
pub fn serve_linux_vault(service: &VaultService, options: &LinuxVaultOptions) -> VaultResult<()> {
    validate_socket_options("Linux", &options.socket_path, options.poll_interval)?;
    prepare_socket_path(&options.socket_path)?;
    let listener = UnixListener::bind(&options.socket_path)
        .map_err(|error| path_io_error(&options.socket_path, &error))?;
    fs::set_permissions(&options.socket_path, fs::Permissions::from_mode(0o600))
        .map_err(|error| path_io_error(&options.socket_path, &error))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| path_io_error(&options.socket_path, &error))?;
    let _socket_guard = SocketGuard::new(options.socket_path.clone());

    let stopping = Arc::new(AtomicBool::new(false));
    let lifecycle_seal_requested = Arc::new(AtomicBool::new(false));
    let lifecycle_monitor = options
        .install_lifecycle_monitor
        .then(|| LinuxLifecycleMonitor::new(&lifecycle_seal_requested))
        .transpose()?;
    if options.install_signal_handler {
        let signal_stopping = Arc::clone(&stopping);
        ctrlc::set_handler(move || signal_stopping.store(true, Ordering::Release)).map_err(
            |error| VaultError::Protocol(format!("could not install signal handler: {error}")),
        )?;
    }

    // Every exit from the loop discards the hardware-unwrapped keys, including
    // the error exits. Returning `?` straight out of the loop skipped the lock
    // and left them to whatever the caller did next.
    let served = accept_until_sealed(
        service,
        options,
        &listener,
        &stopping,
        &lifecycle_seal_requested,
        lifecycle_monitor.as_ref(),
    );
    let sealed = service.seal();
    served.and(sealed)
}

fn accept_until_sealed(
    service: &VaultService,
    options: &LinuxVaultOptions,
    listener: &UnixListener,
    stopping: &AtomicBool,
    lifecycle_seal_requested: &AtomicBool,
    lifecycle_monitor: Option<&LinuxLifecycleMonitor>,
) -> VaultResult<()> {
    let caller_cache = CallerIdentityCache::default();
    while !stopping.load(Ordering::Acquire) {
        if let Some(monitor) = lifecycle_monitor {
            monitor.process()?;
        }
        if lifecycle_seal_requested.load(Ordering::Acquire) {
            return Ok(());
        }
        if service.expire_if_needed(unix_time()?)? {
            return Ok(());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // A malformed or disconnected client must not terminate the
                // per-user vault. Protocol responses intentionally contain no
                // request details when a frame cannot be authenticated.
                let _ = handle_connection(service, &caller_cache, &mut stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(options.poll_interval);
            }
            Err(error) => return Err(path_io_error(&options.socket_path, &error)),
        }
    }
    Ok(())
}

/// Owns logind's delay inhibitor until the store has sealed. Dropping the
/// returned file descriptor releases suspend or shutdown to continue.
struct LinuxLifecycleMonitor {
    connection: Connection,
    _delay_inhibitor: OwnedFd,
}

impl LinuxLifecycleMonitor {
    fn new(lock_requested: &Arc<AtomicBool>) -> VaultResult<Self> {
        let connection = Connection::new_system().map_err(|error| lifecycle_error(&error))?;
        let manager = connection.with_proxy(
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            LIFECYCLE_DBUS_TIMEOUT,
        );
        let session_id = SESSION_ID_ENVIRONMENT.iter().find_map(|name| {
            std::env::var(name)
                .ok()
                .filter(|session_id| !session_id.is_empty())
        });
        let (session_path,): (DbusPath<'static>,) = if let Some(session_id) = session_id {
            manager.method_call(
                "org.freedesktop.login1.Manager",
                "GetSession",
                (session_id,),
            )
        } else {
            manager.method_call(
                "org.freedesktop.login1.Manager",
                "GetSessionByPID",
                (std::process::id(),),
            )
        }
        .map_err(|error| lifecycle_error(&error))?;
        let (delay_inhibitor,): (OwnedFd,) = manager
            .method_call(
                "org.freedesktop.login1.Manager",
                "Inhibit",
                (
                    "sleep:shutdown",
                    "Factorseal",
                    "Lock hardware-unwrapped secrets",
                    "delay",
                ),
            )
            .map_err(|error| lifecycle_error(&error))?;

        for member in ["PrepareForSleep", "PrepareForShutdown"] {
            let requested = Arc::clone(lock_requested);
            connection
                .add_match::<(bool,), _>(
                    MatchRule::new_signal("org.freedesktop.login1.Manager", member)
                        .with_path("/org/freedesktop/login1"),
                    move |(starting,), _, _| {
                        if starting {
                            requested.store(true, Ordering::Release);
                        }
                        true
                    },
                )
                .map_err(|error| lifecycle_error(&error))?;
        }

        let requested = Arc::clone(lock_requested);
        connection
            .add_match::<(), _>(
                MatchRule::new_signal("org.freedesktop.login1.Session", "Lock")
                    .with_path(session_path),
                move |(), _, _| {
                    requested.store(true, Ordering::Release);
                    true
                },
            )
            .map_err(|error| lifecycle_error(&error))?;

        Ok(Self {
            connection,
            _delay_inhibitor: delay_inhibitor,
        })
    }

    fn process(&self) -> VaultResult<()> {
        self.connection
            .process(Duration::ZERO)
            .map(|_| ())
            .map_err(|error| lifecycle_error(&error))
    }
}

fn lifecycle_error(error: &dbus::Error) -> VaultError {
    VaultError::Protocol(format!(
        "could not monitor Linux session lifecycle: {error}"
    ))
}

/// Build the same caller identity that the socket transport will derive for a
/// future connection from `executable`. This is used by an offline grant tool;
/// replacing the executable changes its digest and invalidates the grant.
pub fn linux_caller_identity_for_executable(
    executable: impl AsRef<Path>,
) -> VaultResult<CallerIdentity> {
    let executable = executable.as_ref();
    let executable_path =
        fs::canonicalize(executable).map_err(|error| path_io_error(executable, &error))?;
    let executable_digest = hash_file(&executable_path)?;
    CallerIdentity::new(
        CallerPlatform::Linux,
        format!("uid:{}", getuid().as_raw()),
        executable_path.to_string_lossy().into_owned(),
        executable_digest,
        None,
    )
}

fn handle_connection(
    service: &VaultService,
    caller_cache: &CallerIdentityCache,
    stream: &mut UnixStream,
) -> VaultResult<()> {
    stream
        .set_nonblocking(true)
        .map_err(|error| VaultError::Protocol(format!("could not bound client I/O: {error}")))?;
    let caller = caller_identity(stream, caller_cache)?;
    let bytes = read_frame(stream, IoBudget::new(IPC_FRAME_IO_TIMEOUT))?;
    let request = VaultRequest::decode(&bytes)?;
    let response = service.handle(&caller, request, unix_time()?);
    let bytes = response.encode()?;
    // The response gets its own budget so a slow store operation cannot make
    // the vault drop a reply it has already committed.
    write_frame(stream, &bytes, IoBudget::new(IPC_FRAME_IO_TIMEOUT))
}

fn caller_identity(
    stream: &UnixStream,
    cache: &CallerIdentityCache,
) -> VaultResult<CallerIdentity> {
    let credentials = getsockopt(stream, PeerCredentials).map_err(|error| {
        VaultError::Protocol(format!("could not read peer credentials: {error}"))
    })?;
    let expected_uid = getuid().as_raw();
    if credentials.uid() != expected_uid {
        return Err(VaultError::AuthorizationRequired);
    }
    let pid = credentials.pid();
    if pid <= 0 {
        return Err(VaultError::Protocol(
            "local peer has an invalid process ID".to_owned(),
        ));
    }
    let executable_link = PathBuf::from(format!("/proc/{pid}/exe"));
    // `SO_PEERCRED` reports the PID captured at connect time, and a PID is
    // reusable, so the process behind this link is only the peer if it has not
    // been replaced since. Reading the start time on both sides of the
    // resolution rejects a reused PID.
    let start_time = process_start_time(pid)?;
    let executable_path =
        fs::read_link(&executable_link).map_err(|error| path_io_error(&executable_link, &error))?;
    // Everything below reads one opened descriptor rather than the path, so
    // the digest, the size, and the inode all describe the same image even if
    // the peer executes something else meanwhile.
    let mut executable =
        File::open(&executable_link).map_err(|error| path_io_error(&executable_link, &error))?;
    let metadata = executable
        .metadata()
        .map_err(|error| path_io_error(&executable_link, &error))?;
    let cache_key = format!(
        "{}:{pid}:{start_time}:{}:{}:{}:{}:{}",
        credentials.uid(),
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec()
    );
    let identity = cache.resolve(cache_key, || {
        let executable_digest = hash_open_file(&mut executable, &executable_link)?;
        CallerIdentity::new(
            CallerPlatform::Linux,
            format!("uid:{}", credentials.uid()),
            executable_path.to_string_lossy().into_owned(),
            executable_digest,
            None,
        )
    })?;
    if process_start_time(pid)? != start_time {
        return Err(VaultError::AuthorizationRequired);
    }
    Ok(identity)
}

fn process_start_time(pid: i32) -> VaultResult<u64> {
    let path = PathBuf::from(format!("/proc/{pid}/stat"));
    let stat = fs::read_to_string(&path).map_err(|error| path_io_error(&path, &error))?;
    let fields = stat
        .rsplit_once(") ")
        .ok_or_else(|| VaultError::Protocol("peer process stat is malformed".to_owned()))?
        .1;
    fields
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| VaultError::Protocol("peer process start time is missing".to_owned()))?
        .parse()
        .map_err(|_| VaultError::Protocol("peer process start time is invalid".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "hardware")]
    use crate::{
        GrantPermission, UnsealLeasePolicy, Vault, VaultAction, VaultResponseBody, VaultStore,
        WireSecret, WireSecretAddress,
    };
    #[test]
    fn peer_identity_comes_from_socket_credentials() {
        let (left, _right) = UnixStream::pair().unwrap();
        let identity = caller_identity(&left, &CallerIdentityCache::default()).unwrap();
        assert_eq!(identity.platform(), CallerPlatform::Linux);
        assert_eq!(identity.user_id(), format!("uid:{}", getuid().as_raw()));
        assert!(!identity.application_id().is_empty());
        assert_ne!(identity.executable_digest(), &[0; 32]);
    }

    #[test]
    fn offline_identity_matches_the_running_executable() {
        let (left, _right) = UnixStream::pair().unwrap();
        let peer = caller_identity(&left, &CallerIdentityCache::default()).unwrap();
        let offline = linux_caller_identity_for_executable(peer.application_id()).unwrap();
        assert_eq!(offline, peer);
    }

    #[test]
    fn socket_parent_must_be_private() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let options = LinuxVaultOptions::new(directory.path().join("factorseal.sock"));
        assert!(
            validate_socket_options("Linux", &options.socket_path, options.poll_interval).is_err()
        );
    }

    #[test]
    #[cfg(feature = "hardware")]
    fn a_failing_event_loop_still_seals_the_vault() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unsealed = Vault::create_for_test(&root).unwrap();
        let store = VaultStore::open(&root, unsealed).unwrap();
        let service =
            VaultService::new(store, unix_time().unwrap(), UnsealLeasePolicy::default()).unwrap();

        // A panicking request poisons the request-state mutex, so the first
        // expire_if_needed of the loop fails rather than returning cleanly.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            service.poison_state_for_test();
        }));
        assert!(poisoned.is_err());

        let options = LinuxVaultOptions {
            socket_path: root.join("test-factorseal.sock"),
            poll_interval: Duration::from_millis(5),
            install_signal_handler: false,
            install_lifecycle_monitor: false,
        };
        assert!(serve_linux_vault(&service, &options).is_err());
        assert!(
            service.expire_if_needed(unix_time().unwrap()).unwrap(),
            "an error exit must still discard the unwrapped keys"
        );
        assert!(!options.socket_path.exists());
    }

    #[test]
    fn production_options_require_lifecycle_monitoring() {
        let options = LinuxVaultOptions::new("/run/user/1000/factorseal/factorseal.sock");
        assert!(options.install_signal_handler);
        assert!(options.install_lifecycle_monitor);
    }

    #[test]
    fn session_lock_match_uses_an_exact_object_path() {
        let path = DbusPath::from("/org/freedesktop/login1/session/_32").into_static();
        let rule =
            MatchRule::new_signal("org.freedesktop.login1.Session", "Lock").with_path(path.clone());

        assert_eq!(rule.path, Some(path));
        assert!(!rule.path_is_namespace);
    }

    #[test]
    #[cfg(feature = "hardware")]
    fn native_transport_round_trips_and_seals() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unsealed = Vault::create_for_test(&root).unwrap();
        let store = VaultStore::open(&root, unsealed).unwrap();
        let now = unix_time().unwrap();
        let service =
            Arc::new(VaultService::new(store, now, UnsealLeasePolicy::default()).unwrap());
        let caller =
            linux_caller_identity_for_executable(std::env::current_exe().unwrap()).unwrap();
        let namespace = b"native-transport-test";
        service
            .authorize_namespace(
                &caller,
                namespace,
                [
                    GrantPermission::Get,
                    GrantPermission::Put,
                    GrantPermission::Seal,
                ],
                None,
                now,
            )
            .unwrap();

        let socket = root.join("test-factorseal.sock");
        let options = LinuxVaultOptions {
            socket_path: socket.clone(),
            poll_interval: Duration::from_millis(5),
            install_signal_handler: false,
            install_lifecycle_monitor: false,
        };
        let server_service = Arc::clone(&service);
        let server = std::thread::spawn(move || serve_linux_vault(&server_service, &options));
        let client = LinuxVaultClient::new(socket);
        wait_until_ready(&client, &server);

        let address = WireSecretAddress::new("project/default/TOKEN", None);
        let stored = client
            .request(
                &VaultRequest::new(VaultAction::Put {
                    namespace: namespace.to_vec(),
                    address: address.clone(),
                    value: WireSecret::new(b"transport-secret".to_vec()),
                    evict_at: None,
                })
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(stored.result, Ok(VaultResponseBody::Stored)));

        let fetched = client
            .request(
                &VaultRequest::new(VaultAction::Get {
                    namespace: namespace.to_vec(),
                    address,
                })
                .unwrap(),
            )
            .unwrap();
        let Ok(VaultResponseBody::Secret { value: Some(value) }) = fetched.result else {
            panic!("expected secret response");
        };
        assert_eq!(value.expose(), b"transport-secret");

        let sealed = client
            .request(
                &VaultRequest::new(VaultAction::Seal {
                    namespace: namespace.to_vec(),
                })
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(sealed.result, Ok(VaultResponseBody::Sealed)));
        server.join().unwrap().unwrap();
    }

    /// Wait for the server thread to reach its accept loop.
    ///
    /// The retry interval bounds what a broken server costs, which yielding
    /// does not: an attempt against a server that will never answer takes
    /// however long its transport takes to refuse. When the wait runs out the
    /// server has usually already failed, and its error is the useful one.
    #[cfg(feature = "hardware")]
    fn wait_until_ready(
        client: &LinuxVaultClient,
        server: &std::thread::JoinHandle<VaultResult<()>>,
    ) {
        let mut last = None;
        for _ in 0..200 {
            let status = VaultRequest::new(VaultAction::Status).unwrap();
            match client.request(&status) {
                Ok(_) => return,
                Err(error) => last = Some(error),
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(
            server.is_finished(),
            "the Linux vault is still serving but unreachable: {last:?}"
        );
        panic!("the Linux vault thread exited during startup: {last:?}");
    }
}

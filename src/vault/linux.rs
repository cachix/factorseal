use std::collections::HashSet;
use std::fs::{self, File};
use std::os::unix::fs::MetadataExt;
#[cfg(test)]
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use dbus::Path as DbusPath;
use dbus::arg::{OwnedFd, PropMap};
use dbus::blocking::stdintf::org_freedesktop_dbus::Properties;
use dbus::blocking::{Connection, Proxy};
use dbus::message::MatchRule;
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::getuid;

use super::transport::unix_socket::{
    accept_until_sealed, bind_listener, install_shutdown_signal_handler, validate_socket_options,
};
#[cfg(test)]
use super::transport::unix_time;
use super::transport::{hash_file, hash_open_file, path_io_error};
use super::{
    CallerIdentity, CallerIdentityCache, CallerPlatform, LifecycleSignal, VaultError, VaultResult,
    VaultService,
};
#[cfg(all(test, feature = "hardware"))]
use super::{LinuxVaultClient, VaultClient, VaultRequest};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);
const LIFECYCLE_DBUS_TIMEOUT: Duration = Duration::from_secs(5);
const LOGIND_SEAL_DEADLINE: Duration = Duration::from_secs(4);
const SESSION_ID_ENVIRONMENT: [&str; 2] = ["FACTORSEAL_SESSION_ID", "XDG_SESSION_ID"];

/// Linux per-user socket configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxVaultOptions {
    pub socket_path: PathBuf,
    pub poll_interval: Duration,
    /// Install SIGINT/SIGTERM handlers. Disable only when embedding the server
    /// in a process that owns signal handling itself.
    pub install_signal_handler: bool,
    /// Require systemd-logind sleep and shutdown monitoring, plus session-lock
    /// monitoring when this process belongs to a logind session. Disable only
    /// when an embedding process supplies equivalent hooks.
    pub install_lifecycle_monitor: bool,
    /// Publish `org.freedesktop.secrets` on the session bus. Disable only for
    /// embedded and socket-only test servers.
    pub install_secret_service: bool,
}

impl LinuxVaultOptions {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            install_signal_handler: true,
            install_lifecycle_monitor: true,
            install_secret_service: true,
        }
    }
}

/// Serve the shared vault protocol through a same-user Unix socket.
///
/// Caller identity comes from `SO_PEERCRED` and `/proc/<pid>/exe`; no identity
/// field from the request is trusted. This function blocks until explicit
/// lock, lease expiry, session lock, suspend, shutdown, SIGINT, or SIGTERM.
pub fn serve_linux_vault(
    service: &Arc<VaultService>,
    options: &LinuxVaultOptions,
) -> VaultResult<()> {
    let lifecycle = options
        .install_lifecycle_monitor
        .then(LinuxVaultLifecycle::new)
        .transpose()?;
    if let Some(lifecycle) = lifecycle.as_ref() {
        lifecycle.arm()?;
    }
    let result = serve_linux_vault_with_lifecycle(service, options, lifecycle.as_ref());
    if let Some(lifecycle) = lifecycle.as_ref() {
        lifecycle.disarm();
    }
    result
}

/// Serve with a lifecycle subscription established before vault unsealing.
#[doc(hidden)]
pub fn serve_linux_vault_with_lifecycle(
    service: &Arc<VaultService>,
    options: &LinuxVaultOptions,
    lifecycle_monitor: Option<&LinuxVaultLifecycle>,
) -> VaultResult<()> {
    validate_socket_options("Linux", &options.socket_path, options.poll_interval)?;
    let (listener, _socket_guard) = bind_listener(&options.socket_path)?;

    let stopping = Arc::new(AtomicBool::new(false));
    if let Some(monitor) = lifecycle_monitor {
        monitor.attach(service)?;
    } else if options.install_lifecycle_monitor {
        return Err(VaultError::Protocol(
            "Linux lifecycle monitor was not prepared".to_owned(),
        ));
    }
    if options.install_signal_handler {
        install_shutdown_signal_handler(&stopping)?;
    }

    // Every exit from the loop discards the hardware-unwrapped keys, including
    // the error exits. Returning `?` straight out of the loop skipped the lock
    // and left them to whatever the caller did next.
    // A systemd user manager provides the session bus on desktop Linux. Keep
    // headless CLI/acceptance runs functional when there is no user bus to
    // publish the optional desktop compatibility interface on.
    let has_session_bus =
        options.install_secret_service && std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
    let served = std::thread::scope(|scope| {
        let secret_service = has_session_bus.then(|| {
            let service = Arc::clone(service);
            let stopping = Arc::clone(&stopping);
            scope.spawn(move || super::secret_service::serve_secret_service(service, stopping))
        });
        let caller_cache = CallerIdentityCache::default();
        let result = accept_until_sealed(
            service,
            &listener,
            &stopping,
            &options.socket_path,
            options.poll_interval,
            || Ok(lifecycle_monitor.is_some_and(LinuxVaultLifecycle::requested)),
            |stream| caller_identity(stream, &caller_cache),
        );
        stopping.store(true, Ordering::Release);
        if let Some(thread) = secret_service {
            thread
                .join()
                .map_err(|_| VaultError::Protocol("Secret Service thread panicked".to_owned()))??;
        }
        result
    });
    let sealed = service.seal();
    served.and(sealed)
}

/// Owns logind's delay inhibitor until the store has sealed. Dropping the
/// returned file descriptor releases suspend or shutdown to continue.
#[doc(hidden)]
pub struct LinuxVaultLifecycle {
    signal: Arc<LifecycleSignal>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl LinuxVaultLifecycle {
    pub fn new() -> VaultResult<Self> {
        let signal = Arc::new(LifecycleSignal::new());
        let stopping = Arc::new(AtomicBool::new(false));
        let (ready_sender, ready_receiver) = sync_channel(1);
        let thread_signal = Arc::clone(&signal);
        let thread_stopping = Arc::clone(&stopping);
        let thread = std::thread::Builder::new()
            .name("factorseal-linux-lifecycle".to_owned())
            .spawn(move || {
                let monitor = match LinuxLifecycleConnection::new(Arc::clone(&thread_signal)) {
                    Ok(monitor) => {
                        if ready_sender.send(Ok(())).is_err() {
                            return;
                        }
                        monitor
                    }
                    Err(error) => {
                        let _ = ready_sender.send(Err(error.to_string()));
                        return;
                    }
                };
                while !thread_stopping.load(Ordering::Acquire) {
                    if monitor.process(DEFAULT_POLL_INTERVAL).is_err() {
                        // Losing lifecycle monitoring is itself fail closed.
                        thread_signal.trigger();
                        abort_if_unsealed(&thread_signal);
                        break;
                    }
                }
            })
            .map_err(|error| {
                VaultError::Protocol(format!("could not start Linux lifecycle monitor: {error}"))
            })?;
        ready_receiver
            .recv()
            .map_err(|_| {
                VaultError::Protocol("Linux lifecycle monitor stopped during startup".to_owned())
            })?
            .map_err(VaultError::Protocol)?;
        Ok(Self {
            signal,
            stopping,
            thread: Some(thread),
        })
    }

    pub fn arm(&self) -> VaultResult<()> {
        self.signal.arm()
    }

    pub fn disarm(&self) {
        self.signal.disarm();
    }

    #[must_use]
    pub fn requested(&self) -> bool {
        self.signal.requested()
    }

    fn attach(&self, service: &Arc<VaultService>) -> VaultResult<()> {
        self.signal.attach(service)
    }
}

impl Drop for LinuxVaultLifecycle {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct LinuxLifecycleConnection {
    connection: Connection,
    _delay_inhibitor: OwnedFd,
    signal: Arc<LifecycleSignal>,
    session_paths: Arc<Mutex<HashSet<String>>>,
    sessions_changed: Arc<AtomicBool>,
}

impl LinuxLifecycleConnection {
    #[expect(
        clippy::too_many_lines,
        reason = "keeping all logind registrations together makes their fail-closed setup auditable"
    )]
    fn new(signal: Arc<LifecycleSignal>) -> VaultResult<Self> {
        let connection = Connection::new_system().map_err(|error| lifecycle_error(&error))?;
        let session_paths = Arc::new(Mutex::new(HashSet::new()));
        let sessions_changed = Arc::new(AtomicBool::new(false));
        let (delay_inhibitor,): (OwnedFd,) = connection
            .with_proxy(
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                LIFECYCLE_DBUS_TIMEOUT,
            )
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

        let sleep_signal = Arc::clone(&signal);
        connection
            .add_match::<(bool,), _>(
                MatchRule::new_signal("org.freedesktop.login1.Manager", "PrepareForSleep")
                    .with_path("/org/freedesktop/login1"),
                move |(starting,), _, _| {
                    // The false edge is a resume fallback if the pre-sleep
                    // edge was lost. A correctly handled true edge has
                    // already stopped the process before this can arrive.
                    if starting {
                        start_logind_deadline(Arc::clone(&sleep_signal));
                    }
                    sleep_signal.trigger();
                    if !starting {
                        abort_if_unsealed(&sleep_signal);
                    }
                    true
                },
            )
            .map_err(|error| lifecycle_error(&error))?;

        let shutdown_signal = Arc::clone(&signal);
        connection
            .add_match::<(bool,), _>(
                MatchRule::new_signal("org.freedesktop.login1.Manager", "PrepareForShutdown")
                    .with_path("/org/freedesktop/login1"),
                move |(starting,), _, _| {
                    if starting {
                        start_logind_deadline(Arc::clone(&shutdown_signal));
                        shutdown_signal.trigger();
                    }
                    true
                },
            )
            .map_err(|error| lifecycle_error(&error))?;

        let lock_signal = Arc::clone(&signal);
        let lock_paths = Arc::clone(&session_paths);
        connection
            .add_match::<(), _>(
                MatchRule::new_signal("org.freedesktop.login1.Session", "Lock"),
                move |(), _, message| {
                    if message_path_is_tracked(
                        message.path().map(|path| path.to_string()),
                        &lock_paths,
                    ) {
                        lock_signal.trigger();
                        abort_if_unsealed(&lock_signal);
                    }
                    true
                },
            )
            .map_err(|error| lifecycle_error(&error))?;

        let hint_signal = Arc::clone(&signal);
        let hint_paths = Arc::clone(&session_paths);
        connection
            .add_match::<(String, PropMap, Vec<String>), _>(
                MatchRule::new_signal("org.freedesktop.DBus.Properties", "PropertiesChanged"),
                move |(interface, changed, _invalidated), _, message| {
                    if interface == "org.freedesktop.login1.Session"
                        && locked_hint_is_true(&changed)
                        && message_path_is_tracked(
                            message.path().map(|path| path.to_string()),
                            &hint_paths,
                        )
                    {
                        hint_signal.trigger();
                        abort_if_unsealed(&hint_signal);
                    }
                    true
                },
            )
            .map_err(|error| lifecycle_error(&error))?;

        for member in ["SessionNew", "SessionRemoved"] {
            let changed = Arc::clone(&sessions_changed);
            connection
                .add_match::<(String, DbusPath<'static>), _>(
                    MatchRule::new_signal("org.freedesktop.login1.Manager", member)
                        .with_path("/org/freedesktop/login1"),
                    move |_, _, _| {
                        changed.store(true, Ordering::Release);
                        true
                    },
                )
                .map_err(|error| lifecycle_error(&error))?;
        }

        let monitor = Self {
            connection,
            _delay_inhibitor: delay_inhibitor,
            signal,
            session_paths,
            sessions_changed,
        };
        let manager = monitor.connection.with_proxy(
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            LIFECYCLE_DBUS_TIMEOUT,
        );
        monitor.refresh_sessions(&manager)?;
        Ok(monitor)
    }

    /// Track every logind session for this user, plus an explicitly selected
    /// session. `LockedHint` is the actual lock state; `Lock` remains an eager
    /// fallback for compositors that update the property late.
    fn refresh_sessions(&self, manager: &Proxy<'_, &Connection>) -> VaultResult<()> {
        type Session = (String, u32, String, String, DbusPath<'static>);
        let (sessions,): (Vec<Session>,) = manager
            .method_call("org.freedesktop.login1.Manager", "ListSessions", ())
            .map_err(|error| lifecycle_error(&error))?;
        let expected_uid = getuid().as_raw();
        let mut paths: HashSet<String> = sessions
            .into_iter()
            .filter(|(_, uid, _, _, _)| *uid == expected_uid)
            .map(|(_, _, _, _, path)| path.to_string())
            .collect();

        let explicit_session = SESSION_ID_ENVIRONMENT.iter().find_map(|name| {
            std::env::var(name)
                .ok()
                .filter(|session_id| !session_id.is_empty())
        });
        if let Some(session_id) = explicit_session {
            let (session_path,): (DbusPath<'static>,) = manager
                .method_call(
                    "org.freedesktop.login1.Manager",
                    "GetSession",
                    (session_id,),
                )
                .map_err(|error| lifecycle_error(&error))?;
            paths.insert(session_path.to_string());
        }

        for path in &paths {
            let session = self.connection.with_proxy(
                "org.freedesktop.login1",
                path.as_str(),
                LIFECYCLE_DBUS_TIMEOUT,
            );
            let locked: bool = session
                .get("org.freedesktop.login1.Session", "LockedHint")
                .map_err(|error| lifecycle_error(&error))?;
            if locked {
                self.signal.trigger();
            }
        }
        *self
            .session_paths
            .lock()
            .map_err(|_| VaultError::WorkerUnavailable)? = paths;
        self.sessions_changed.store(false, Ordering::Release);
        Ok(())
    }

    fn process(&self, timeout: Duration) -> VaultResult<()> {
        self.connection
            .process(timeout)
            .map(|_| ())
            .map_err(|error| lifecycle_error(&error))?;
        if self.sessions_changed.load(Ordering::Acquire) {
            let manager = self.connection.with_proxy(
                "org.freedesktop.login1",
                "/org/freedesktop/login1",
                LIFECYCLE_DBUS_TIMEOUT,
            );
            self.refresh_sessions(&manager)?;
        }
        Ok(())
    }
}

fn message_path_is_tracked(path: Option<String>, paths: &Mutex<HashSet<String>>) -> bool {
    let Some(path) = path else {
        return false;
    };
    paths
        .lock()
        .map_or(true, |paths| paths.contains(path.as_str()))
}

fn locked_hint_is_true(changed: &PropMap) -> bool {
    changed
        .get("LockedHint")
        .and_then(|value| value.0.as_i64())
        .is_some_and(|value| value != 0)
}

fn abort_if_unsealed(signal: &LifecycleSignal) {
    if signal.needs_emergency_exit() {
        std::process::abort();
    }
}

fn start_logind_deadline(signal: Arc<LifecycleSignal>) {
    if std::thread::Builder::new()
        .name("factorseal-logind-deadline".to_owned())
        .spawn(move || {
            std::thread::sleep(LOGIND_SEAL_DEADLINE);
            abort_if_unsealed(&signal);
        })
        .is_err()
    {
        std::process::abort();
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
        DocumentKind, GrantPermission, SecretSpecAddress, UnsealLeasePolicy, Vault, VaultAction,
        VaultApplicationContext, VaultResponseBody, WireSecret, WireSecretAddress,
        vault::VaultStore,
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
        let service = Arc::new(
            VaultService::new(store, unix_time().unwrap(), UnsealLeasePolicy::default()).unwrap(),
        );

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
            install_secret_service: false,
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
        assert!(options.install_secret_service);
    }

    #[test]
    fn session_lock_events_are_filtered_to_tracked_user_sessions() {
        let paths = Mutex::new(HashSet::from([
            "/org/freedesktop/login1/session/_32".to_owned()
        ]));

        assert!(message_path_is_tracked(
            Some("/org/freedesktop/login1/session/_32".to_owned()),
            &paths
        ));
        assert!(!message_path_is_tracked(
            Some("/org/freedesktop/login1/session/_99".to_owned()),
            &paths
        ));
        assert!(!message_path_is_tracked(None, &paths));
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
            install_secret_service: false,
        };
        let server_service = Arc::clone(&service);
        let server = std::thread::spawn(move || serve_linux_vault(&server_service, &options));
        let client = LinuxVaultClient::new(socket);
        wait_until_ready(&client, &server);
        assert_approval_wait_allows_concurrent_request(&service, &caller, &client, now);

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
        assert_project_listing_round_trips(&service, &caller, &client, now);

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

    #[cfg(feature = "hardware")]
    fn assert_project_listing_round_trips(
        service: &VaultService,
        caller: &CallerIdentity,
        client: &LinuxVaultClient,
        now: u64,
    ) {
        service
            .authorize_document_kind(
                caller,
                DocumentKind::SecretSpecProject,
                [GrantPermission::List, GrantPermission::Put],
                None,
                now,
            )
            .unwrap();
        let address = SecretSpecAddress::convention("transport", "default", "TOKEN").unwrap();
        let stored = client
            .request(
                &VaultRequest::new(VaultAction::PutProject {
                    project: "transport".to_owned(),
                    address: address.clone(),
                    value: WireSecret::new(b"project-secret".to_vec()),
                })
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(stored.result, Ok(VaultResponseBody::Stored)));

        let projects = client
            .request(
                &VaultRequest::new(VaultAction::ListProjects {
                    cursor: None,
                    limit: 1,
                })
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            projects.result,
            Ok(VaultResponseBody::Projects { projects, .. }) if projects == ["transport"]
        ));

        let addresses = client
            .request(
                &VaultRequest::new(VaultAction::ListProjectAddresses {
                    project: "transport".to_owned(),
                    cursor: None,
                    limit: 1,
                })
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            addresses.result,
            Ok(VaultResponseBody::ProjectAddresses { addresses, .. }) if addresses == [address]
        ));
    }

    #[cfg(feature = "hardware")]
    fn assert_approval_wait_allows_concurrent_request(
        service: &VaultService,
        caller: &CallerIdentity,
        client: &LinuxVaultClient,
        now: u64,
    ) {
        service.authorize_permission_manager(caller, now).unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let wait_barrier = Arc::clone(&barrier);
        let wait_client = client.clone();
        let wait = std::thread::spawn(move || {
            wait_barrier.wait();
            wait_client
                .request(
                    &VaultRequest::new(VaultAction::WaitPermissions {
                        after_revision: 0,
                        timeout_ms: 2_000,
                    })
                    .unwrap(),
                )
                .unwrap()
        });
        barrier.wait();
        // Give the watcher time to enter its bounded wait. With a serial
        // accept loop, the provider request below cannot then create the
        // approval that wakes it.
        std::thread::sleep(Duration::from_millis(50));

        let application = VaultApplicationContext::new(
            Some("transport-project".to_owned()),
            Some("default".to_owned()),
            None,
            Some("test native notification".to_owned()),
        )
        .unwrap();
        let denied = client
            .request(
                &VaultRequest::new_with_application(
                    VaultAction::GetCache {
                        project: "transport-project".to_owned(),
                        address: crate::vault::SecretSpecAddress::convention(
                            "transport-project",
                            "default",
                            "TOKEN",
                        )
                        .unwrap(),
                    },
                    application,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(denied.result.unwrap_err().interaction.is_some());
        assert!(matches!(
            wait.join().unwrap().result,
            Ok(VaultResponseBody::Permissions {
                revision,
                permissions
            }) if revision > 0 && permissions.len() == 1
        ));
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

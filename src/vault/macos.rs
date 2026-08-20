//! macOS vault transport and lifecycle integration.
//!
//! Objective-C notification registration is isolated in this module. The
//! generated bindings mark observer registration and removal unsafe because
//! Objective-C cannot express Rust's type invariants; all retained objects and
//! block argument types below match the AppKit declarations.

#![allow(unsafe_code)]

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use block2::RcBlock;
use nix::sys::socket::{
    getsockopt,
    sockopt::{LocalPeerCred, LocalPeerPid, LocalPeerToken},
};
use nix::unistd::getuid;
use objc2::rc::Retained;
use objc2::runtime::AnyObject;
use objc2_app_kit::{
    NSWorkspace, NSWorkspaceSessionDidResignActiveNotification,
    NSWorkspaceWillPowerOffNotification, NSWorkspaceWillSleepNotification,
};
use objc2_foundation::{NSDate, NSNotification, NSNotificationCenter, NSRunLoop};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

use super::transport::unix_socket::{SocketGuard, prepare_socket_path, validate_socket_options};
use super::transport::{
    IPC_FRAME_IO_TIMEOUT, IoBudget, hash_file, hash_open_file, path_io_error, read_frame,
    unix_time, write_frame,
};
use super::{
    CallerIdentity, CallerIdentityCache, CallerPlatform, VaultError, VaultRequest, VaultResult,
    VaultService,
};
#[cfg(test)]
use super::{MacosVaultClient, VaultClient};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// macOS per-user socket configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MacosVaultOptions {
    pub socket_path: PathBuf,
    pub poll_interval: Duration,
    /// Install SIGINT/SIGTERM handlers. Disable only when the embedding
    /// process supplies equivalent lifecycle handling.
    pub install_signal_handler: bool,
    /// Require AppKit sleep, power-off, and session-switch notifications.
    /// Disable only when the embedding process supplies equivalent hooks.
    pub install_lifecycle_monitor: bool,
}

impl MacosVaultOptions {
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

/// Serve through a private Unix socket authenticated with macOS kernel peer
/// credentials, peer PID, and audit token.
pub fn serve_macos_vault(
    service: &Arc<VaultService>,
    options: &MacosVaultOptions,
) -> VaultResult<()> {
    validate_socket_options("macOS", &options.socket_path, options.poll_interval)?;
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
    let lifecycle_monitor = options
        .install_lifecycle_monitor
        .then(|| MacosLifecycleMonitor::new(service, &stopping));
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
        lifecycle_monitor.as_ref(),
    );
    let sealed = service.seal();
    served.and(sealed)
}

fn accept_until_sealed(
    service: &VaultService,
    options: &MacosVaultOptions,
    listener: &UnixListener,
    stopping: &AtomicBool,
    lifecycle_monitor: Option<&MacosLifecycleMonitor>,
) -> VaultResult<()> {
    let caller_cache = CallerIdentityCache::default();
    while !stopping.load(Ordering::Acquire) {
        if let Some(monitor) = lifecycle_monitor {
            monitor.process();
        }
        if service.expire_if_needed(unix_time()?)? {
            return Ok(());
        }
        match listener.accept() {
            Ok((mut stream, _)) => {
                // A malformed or disconnected client must not terminate the
                // per-user vault.
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

struct MacosLifecycleMonitor {
    notification_center: Retained<NSNotificationCenter>,
    observers: Vec<Retained<AnyObject>>,
    run_loop: Retained<NSRunLoop>,
}

impl MacosLifecycleMonitor {
    fn new(service: &Arc<VaultService>, stopping: &Arc<AtomicBool>) -> Self {
        let workspace = NSWorkspace::sharedWorkspace();
        let notification_center = workspace.notificationCenter();
        let mut observers = Vec::with_capacity(3);

        // SAFETY: These are AppKit-owned static notification names, and the
        // block's NonNull<NSNotification> argument exactly matches the
        // generated Objective-C method signature. The center copies the block.
        for name in unsafe {
            [
                NSWorkspaceWillSleepNotification,
                NSWorkspaceWillPowerOffNotification,
                NSWorkspaceSessionDidResignActiveNotification,
            ]
        } {
            let lifecycle_service = Arc::clone(service);
            let lifecycle_stopping = Arc::clone(stopping);
            let block = RcBlock::new(move |_notification: NonNull<NSNotification>| {
                // Lock synchronously before returning from the pre-sleep or
                // session callback; the event-loop poll is not the security
                // boundary for zeroizing hardware-unwrapped keys.
                let _ = lifecycle_service.seal();
                lifecycle_stopping.store(true, Ordering::Release);
            });
            let observer = unsafe {
                notification_center.addObserverForName_object_queue_usingBlock(
                    Some(name),
                    None,
                    None,
                    &block,
                )
            };
            observers.push(observer.into());
        }

        Self {
            notification_center,
            observers,
            run_loop: NSRunLoop::currentRunLoop(),
        }
    }

    fn process(&self) {
        self.run_loop
            .runUntilDate(&NSDate::dateWithTimeIntervalSinceNow(0.0));
    }
}

impl Drop for MacosLifecycleMonitor {
    fn drop(&mut self) {
        for observer in &self.observers {
            // SAFETY: Each retained token was returned by this exact
            // notification center's block-observer registration method.
            unsafe { self.notification_center.removeObserver(observer) };
        }
    }
}

/// Construct the identity used for an offline executable grant.
pub fn macos_caller_identity_for_executable(
    executable: impl AsRef<Path>,
) -> VaultResult<CallerIdentity> {
    let executable = executable.as_ref();
    let executable_path =
        fs::canonicalize(executable).map_err(|error| path_io_error(executable, &error))?;
    CallerIdentity::new(
        CallerPlatform::Macos,
        format!("uid:{}", getuid().as_raw()),
        executable_path.to_string_lossy().into_owned(),
        hash_file(&executable_path)?,
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
    let credentials = getsockopt(stream, LocalPeerCred).map_err(|error| {
        VaultError::Protocol(format!("could not read peer credentials: {error}"))
    })?;
    if credentials.uid() != getuid().as_raw() {
        return Err(VaultError::AuthorizationRequired);
    }
    let pid = getsockopt(stream, LocalPeerPid)
        .map_err(|error| VaultError::Protocol(format!("could not read peer PID: {error}")))?;
    if pid <= 0 {
        return Err(VaultError::Protocol(
            "local peer has an invalid process ID".to_owned(),
        ));
    }
    // Requiring the kernel audit token prevents a transport that merely
    // supplies a PID/UID from being treated as authenticated on macOS.
    let _audit_token = getsockopt(stream, LocalPeerToken).map_err(|error| {
        VaultError::Protocol(format!("could not read peer audit token: {error}"))
    })?;
    let (executable_path, start_time) = process_executable(pid)?;
    // Everything below reads one opened descriptor rather than the path, so
    // the digest, the size, and the inode all describe the same image even if
    // the peer executes something else meanwhile.
    let mut executable =
        File::open(&executable_path).map_err(|error| path_io_error(&executable_path, &error))?;
    let metadata = executable
        .metadata()
        .map_err(|error| path_io_error(&executable_path, &error))?;
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
        CallerIdentity::new(
            CallerPlatform::Macos,
            format!("uid:{}", credentials.uid()),
            executable_path.to_string_lossy().into_owned(),
            hash_open_file(&mut executable, &executable_path)?,
            None,
        )
    })?;
    // The peer PID was captured at connect time and a PID is reusable, so the
    // process must still be the one that connected.
    if process_executable(pid)?.1 != start_time {
        return Err(VaultError::AuthorizationRequired);
    }
    Ok(identity)
}

/// Resolve one process without enumerating the machine.
///
/// `System::new_all()` scanned every process and all hardware on every
/// incoming connection, and it ran before the caller-identity cache could
/// avoid it, so a cache hit paid for it too.
fn process_executable(process_id: i32) -> VaultResult<(PathBuf, u64)> {
    let process_id = u32::try_from(process_id)
        .map_err(|_| VaultError::Protocol("peer PID is outside the supported range".to_owned()))?;
    let process_id = Pid::from_u32(process_id);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[process_id]),
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let process = system
        .process(process_id)
        .ok_or_else(|| VaultError::Protocol("could not resolve client executable".to_owned()))?;
    let executable = process
        .exe()
        .ok_or_else(|| VaultError::Protocol("could not resolve client executable".to_owned()))?;
    fs::canonicalize(executable)
        .map(|path| (path, process.start_time()))
        .map_err(|error| VaultError::Protocol(format!("could not resolve client path: {error}")))
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
    fn peer_identity_comes_from_kernel_credentials_and_audit_token() {
        let (left, _right) = UnixStream::pair().unwrap();
        let identity = caller_identity(&left, &CallerIdentityCache::default()).unwrap();
        assert_eq!(identity.platform(), CallerPlatform::Macos);
        assert_eq!(identity.user_id(), format!("uid:{}", getuid().as_raw()));
        assert_ne!(identity.executable_digest(), &[0; 32]);
    }

    #[test]
    fn offline_identity_matches_the_running_executable() {
        let (left, _right) = UnixStream::pair().unwrap();
        let peer = caller_identity(&left, &CallerIdentityCache::default()).unwrap();
        let offline = macos_caller_identity_for_executable(peer.application_id()).unwrap();
        assert_eq!(offline, peer);
    }

    #[test]
    fn socket_parent_must_be_private() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let options = MacosVaultOptions::new(directory.path().join("factorseal.sock"));
        assert!(
            validate_socket_options("macOS", &options.socket_path, options.poll_interval).is_err()
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

        let options = MacosVaultOptions {
            socket_path: root.join("test-factorseal.sock"),
            poll_interval: Duration::from_millis(5),
            install_signal_handler: false,
            install_lifecycle_monitor: false,
        };
        assert!(serve_macos_vault(&service, &options).is_err());
        assert!(
            service.expire_if_needed(unix_time().unwrap()).unwrap(),
            "an error exit must still discard the unwrapped keys"
        );
        assert!(!options.socket_path.exists());
    }

    #[cfg(feature = "hardware")]
    #[test]
    fn appkit_lifecycle_notifications_reach_the_lock_signal() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal-lifecycle");
        let unsealed = Vault::create_for_test(&root).unwrap();
        let store = VaultStore::open(&root, unsealed).unwrap();
        let now = unix_time().unwrap();
        let service =
            Arc::new(VaultService::new(store, now, UnsealLeasePolicy::default()).unwrap());
        let stopping = Arc::new(AtomicBool::new(false));
        let monitor = MacosLifecycleMonitor::new(&service, &stopping);
        // SAFETY: This posts the same AppKit-owned notification name used by
        // registration and carries no dynamically typed object payload.
        unsafe {
            monitor
                .notification_center
                .postNotificationName_object(NSWorkspaceWillSleepNotification, None);
        }
        assert!(stopping.load(Ordering::Acquire));
        assert!(service.expire_if_needed(now).unwrap());
    }

    #[test]
    fn production_options_require_lifecycle_monitoring() {
        let options = MacosVaultOptions::new("/tmp/factorseal/factorseal.sock");
        assert!(options.install_signal_handler);
        assert!(options.install_lifecycle_monitor);
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
            macos_caller_identity_for_executable(std::env::current_exe().unwrap()).unwrap();
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
        let options = MacosVaultOptions {
            socket_path: socket.clone(),
            poll_interval: Duration::from_millis(5),
            install_signal_handler: false,
            install_lifecycle_monitor: false,
        };
        let server_service = Arc::clone(&service);
        let server = std::thread::spawn(move || serve_macos_vault(&server_service, &options));
        let client = MacosVaultClient::new(socket);
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
        client: &MacosVaultClient,
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
            "the macOS vault is still serving but unreachable: {last:?}"
        );
        panic!("the macOS vault thread exited during startup: {last:?}");
    }
}

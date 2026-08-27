//! Windows named-pipe transport with client-token authentication.
//!
//! The only unsafe operations in the crate are isolated here: Win32 requires
//! opening the impersonated thread token so its immutable user SID can be
//! compared with the vault process SID. Handles are immediately transferred
//! into `nt_token::OwnedToken` for RAII ownership.

#![allow(unsafe_code)]

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::thread::JoinHandle;
use std::time::{Duration, UNIX_EPOCH};

use interprocess::os::windows::named_pipe::{
    DuplexPipeStream, PipeListener, PipeListenerOptions, pipe_mode,
};
use interprocess::os::windows::security_descriptor::SecurityDescriptor;
use nt_token::OwnedToken;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use widestring::U16CString;
use windows::Win32::Foundation::{HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::Security::TOKEN_QUERY;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Power::{
    HPOWERNOTIFY, RegisterSuspendResumeNotification, UnregisterSuspendResumeNotification,
};
use windows::Win32::System::RemoteDesktop::{
    NOTIFY_FOR_THIS_SESSION, WTSRegisterSessionNotification, WTSUnRegisterSessionNotification,
};
use windows::Win32::System::Threading::{GetCurrentThread, GetCurrentThreadId, OpenThreadToken};
use windows::Win32::UI::WindowsAndMessaging::{
    CREATESTRUCTW, DEVICE_NOTIFY_WINDOW_HANDLE, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GWLP_USERDATA, GetMessageW, GetWindowLongPtrW, MSG, PBT_APMSUSPEND, PostThreadMessageW,
    RegisterClassW, SetWindowLongPtrW, TranslateMessage, UnregisterClassW, WINDOW_EX_STYLE,
    WINDOW_STYLE, WM_ENDSESSION, WM_NCCREATE, WM_POWERBROADCAST, WM_QUERYENDSESSION, WM_QUIT,
    WM_WTSSESSION_CHANGE, WNDCLASSW, WTS_CONSOLE_DISCONNECT, WTS_REMOTE_DISCONNECT,
    WTS_SESSION_LOCK, WTS_SESSION_LOGOFF,
};
use windows::core::PCWSTR;

use super::transport::{
    IPC_FRAME_IO_TIMEOUT, IoBudget, MAX_ACTIVE_CONNECTIONS, hash_file, hash_open_file,
    pipe_io_error as io_error, read_frame, unix_time, write_frame,
};
use super::windows_client::validate_pipe_name;
use super::{
    CallerIdentity, CallerIdentityCache, CallerPlatform, VaultError, VaultRequest, VaultResult,
    VaultService,
};
#[cfg(test)]
use super::{VaultClient, WindowsVaultClient};

const DEFAULT_POLL_INTERVAL: Duration = Duration::from_millis(100);

type BytePipe = DuplexPipeStream<pipe_mode::Bytes>;
type ByteListener = PipeListener<pipe_mode::Bytes, pipe_mode::Bytes>;

/// Windows per-user named-pipe configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WindowsVaultOptions {
    pub pipe_name: String,
    pub poll_interval: Duration,
    /// Install console termination handlers. Disable only when an embedding
    /// process supplies equivalent lifecycle handling.
    pub install_signal_handler: bool,
    /// Require native suspend, shutdown, logout, disconnect, and session-lock
    /// notifications. Disable only when an embedding process supplies them.
    pub install_lifecycle_monitor: bool,
}

impl WindowsVaultOptions {
    #[must_use]
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
            poll_interval: DEFAULT_POLL_INTERVAL,
            install_signal_handler: true,
            install_lifecycle_monitor: true,
        }
    }
}

/// Serve the shared protocol through a local-only, same-user Windows pipe.
///
/// The pipe DACL permits only the current user, LocalSystem, and
/// administrators. Every accepted connection is additionally impersonated;
/// its token SID and executable digest become the caller identity.
pub fn serve_windows_vault(
    service: &Arc<VaultService>,
    options: &WindowsVaultOptions,
) -> VaultResult<()> {
    validate_options(options)?;
    let security_descriptor = same_user_security_descriptor()?;
    let listener = PipeListenerOptions::new()
        .path(Path::new(&options.pipe_name))
        .nonblocking(true)
        .accept_remote(false)
        .security_descriptor(Some(security_descriptor))
        .create_duplex::<pipe_mode::Bytes>()
        .map_err(|error| io_error("create named pipe", &error))?;

    let stopping = Arc::new(AtomicBool::new(false));
    let _lifecycle_monitor = options
        .install_lifecycle_monitor
        .then(|| WindowsLifecycleMonitor::new(Arc::clone(service), Arc::clone(&stopping)))
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
    let served = accept_until_sealed(service, options, &listener, &stopping);
    let sealed = service.seal();
    served.and(sealed)
}

fn accept_until_sealed(
    service: &VaultService,
    options: &WindowsVaultOptions,
    listener: &ByteListener,
    stopping: &AtomicBool,
) -> VaultResult<()> {
    let caller_cache = CallerIdentityCache::default();
    let active = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        while !stopping.load(Ordering::Acquire) {
            if service.expire_if_needed(unix_time()?)? {
                service.seal()?;
                return Ok(());
            }
            if active.load(Ordering::Acquire) >= MAX_ACTIVE_CONNECTIONS {
                std::thread::sleep(options.poll_interval);
                continue;
            }
            match listener.accept() {
                Ok(mut stream) => {
                    active.fetch_add(1, Ordering::AcqRel);
                    let active = &active;
                    let caller_cache = &caller_cache;
                    if let Err(error) = std::thread::Builder::new()
                        .name("factorseal-ipc".to_owned())
                        .spawn_scoped(scope, move || {
                            let _active = ActiveConnection(active);
                            // A malformed or disconnected client must not
                            // terminate the per-user vault.
                            let _ = handle_connection(service, caller_cache, &mut stream);
                        })
                    {
                        active.fetch_sub(1, Ordering::AcqRel);
                        return Err(VaultError::Protocol(format!(
                            "could not start bounded IPC worker: {error}"
                        )));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(options.poll_interval);
                }
                Err(error) => return Err(io_error("accept named-pipe client", &error)),
            }
        }
        service.seal()?;
        Ok(())
    })
}

struct ActiveConnection<'a>(&'a AtomicUsize);

impl Drop for ActiveConnection<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

struct WindowsLifecycleMonitor {
    thread_id: u32,
    thread: Option<JoinHandle<()>>,
}

impl WindowsLifecycleMonitor {
    fn new(service: Arc<VaultService>, stopping: Arc<AtomicBool>) -> VaultResult<Self> {
        let (ready_sender, ready_receiver) = sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("factorseal-windows-lifecycle".to_owned())
            .spawn(move || lifecycle_message_loop(service, stopping, &ready_sender))
            .map_err(|error| {
                VaultError::Protocol(format!("could not start lifecycle monitor: {error}"))
            })?;
        let thread_id = ready_receiver
            .recv()
            .map_err(|_| {
                VaultError::Protocol("Windows lifecycle monitor stopped during startup".to_owned())
            })?
            .map_err(VaultError::Protocol)?;
        Ok(Self {
            thread_id,
            thread: Some(thread),
        })
    }
}

impl Drop for WindowsLifecycleMonitor {
    fn drop(&mut self) {
        // SAFETY: `thread_id` is reported only after the lifecycle thread has
        // created its message queue. WM_QUIT owns no pointer payload.
        let _ = unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct WindowsLifecycleContext {
    service: Arc<VaultService>,
    stopping: Arc<AtomicBool>,
}

fn lifecycle_message_loop(
    service: Arc<VaultService>,
    stopping: Arc<AtomicBool>,
    ready: &SyncSender<Result<u32, String>>,
) {
    // SAFETY: All Win32 handles, pointers, and callback lifetimes are owned by
    // this thread and cleaned up after its message loop. Startup errors are
    // reported before the server begins accepting secret requests.
    unsafe {
        let module = match GetModuleHandleW(None) {
            Ok(module) => module,
            Err(error) => {
                let _ = ready.send(Err(format!("could not resolve process module: {error}")));
                return;
            }
        };
        let instance = HINSTANCE(module.0);
        let class_name: Vec<u16> = format!(
            "FactorsealLifecycle-{}-{}",
            std::process::id(),
            GetCurrentThreadId()
        )
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
        let class = WNDCLASSW {
            lpfnWndProc: Some(lifecycle_window_proc),
            hInstance: instance,
            lpszClassName: PCWSTR(class_name.as_ptr()),
            ..WNDCLASSW::default()
        };
        if RegisterClassW(&raw const class) == 0 {
            let _ = ready.send(Err(format!(
                "could not register lifecycle window: {}",
                windows::core::Error::from_win32()
            )));
            return;
        }

        let context = Box::new(WindowsLifecycleContext { service, stopping });
        let context_ptr = Box::into_raw(context);
        let window = match windows::Win32::UI::WindowsAndMessaging::CreateWindowExW(
            WINDOW_EX_STYLE(0),
            PCWSTR(class_name.as_ptr()),
            PCWSTR(class_name.as_ptr()),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            None,
            None,
            Some(instance),
            Some(context_ptr.cast()),
        ) {
            Ok(window) => window,
            Err(error) => {
                drop(Box::from_raw(context_ptr));
                let _ = UnregisterClassW(PCWSTR(class_name.as_ptr()), Some(instance));
                let _ = ready.send(Err(format!("could not create lifecycle window: {error}")));
                return;
            }
        };

        if let Err(error) = WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION) {
            cleanup_lifecycle_window(window, None, context_ptr, &class_name, instance);
            let _ = ready.send(Err(format!(
                "could not register session notifications: {error}"
            )));
            return;
        }
        let power = match RegisterSuspendResumeNotification(
            HANDLE(window.0),
            DEVICE_NOTIFY_WINDOW_HANDLE,
        ) {
            Ok(power) => power,
            Err(error) => {
                cleanup_lifecycle_window(window, None, context_ptr, &class_name, instance);
                let _ = ready.send(Err(format!(
                    "could not register suspend notifications: {error}"
                )));
                return;
            }
        };

        if ready.send(Ok(GetCurrentThreadId())).is_err() {
            cleanup_lifecycle_window(window, Some(power), context_ptr, &class_name, instance);
            return;
        }
        let mut message = MSG::default();
        loop {
            let result = GetMessageW(&raw mut message, None, 0, 0).0;
            if result <= 0 {
                break;
            }
            let _ = TranslateMessage(&raw const message);
            DispatchMessageW(&raw const message);
        }
        cleanup_lifecycle_window(window, Some(power), context_ptr, &class_name, instance);
    }
}

unsafe fn cleanup_lifecycle_window(
    window: HWND,
    power: Option<HPOWERNOTIFY>,
    context: *mut WindowsLifecycleContext,
    class_name: &[u16],
    instance: HINSTANCE,
) {
    if let Some(power) = power {
        // SAFETY: The registration handle came from this window and has not
        // previously been unregistered.
        let _ = unsafe { UnregisterSuspendResumeNotification(power) };
    }
    // SAFETY: Registration and window ownership are confined to this thread.
    let _ = unsafe { WTSUnRegisterSessionNotification(window) };
    let _ = unsafe { DestroyWindow(window) };
    // SAFETY: `context` came from Box::into_raw and the window has been
    // destroyed, so no callback can observe it after this point.
    drop(unsafe { Box::from_raw(context) });
    let _ = unsafe { UnregisterClassW(PCWSTR(class_name.as_ptr()), Some(instance)) };
}

unsafe extern "system" fn lifecycle_window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_NCCREATE {
        // SAFETY: WM_NCCREATE supplies a valid CREATESTRUCTW for this callback;
        // lpCreateParams is the boxed context passed to CreateWindowExW.
        let create = unsafe { &*(lparam.0 as *const CREATESTRUCTW) };
        unsafe { SetWindowLongPtrW(window, GWLP_USERDATA, create.lpCreateParams as isize) };
    }
    let context =
        unsafe { GetWindowLongPtrW(window, GWLP_USERDATA) } as *const WindowsLifecycleContext;
    if !context.is_null() && lifecycle_message_requires_lock(message, wparam.0) {
        // SAFETY: The pointer remains owned until after DestroyWindow returns.
        let context = unsafe { &*context };
        let _ = context.service.seal();
        context.stopping.store(true, Ordering::Release);
    }
    // SAFETY: Messages not otherwise consumed retain default Win32 behavior.
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

const fn lifecycle_message_requires_lock(message: u32, parameter: usize) -> bool {
    match message {
        WM_POWERBROADCAST => parameter == PBT_APMSUSPEND as usize,
        WM_QUERYENDSESSION => true,
        WM_ENDSESSION => parameter != 0,
        WM_WTSSESSION_CHANGE => {
            parameter == WTS_SESSION_LOCK as usize
                || parameter == WTS_SESSION_LOGOFF as usize
                || parameter == WTS_CONSOLE_DISCONNECT as usize
                || parameter == WTS_REMOTE_DISCONNECT as usize
        }
        _ => false,
    }
}

/// Construct the caller identity used for an offline executable grant.
pub fn windows_caller_identity_for_executable(
    executable: impl AsRef<Path>,
) -> VaultResult<CallerIdentity> {
    let executable = fs::canonicalize(executable.as_ref()).map_err(|error| {
        VaultError::Protocol(format!("could not canonicalize executable: {error}"))
    })?;
    CallerIdentity::new(
        CallerPlatform::Windows,
        current_process_sid()?,
        executable.to_string_lossy().into_owned(),
        hash_file(&executable)?,
        None,
    )
}

fn handle_connection(
    service: &VaultService,
    caller_cache: &CallerIdentityCache,
    stream: &mut BytePipe,
) -> VaultResult<()> {
    stream
        .set_nonblocking(true)
        .map_err(|error| io_error("configure named pipe", &error))?;
    // Unlike the Unix transports, the request has to be read before the caller
    // can be identified. `ImpersonateNamedPipeClient` has no client token to
    // impersonate until the server has read from the pipe, so identifying
    // first failed every connection and closed it under the client's write.
    // Reading first concedes nothing: the frame is length-bounded before it is
    // parsed, and access is decided by the grant lookup in `handle`.
    let bytes = read_frame(stream, IoBudget::new(IPC_FRAME_IO_TIMEOUT))?;
    let caller = caller_identity(stream, caller_cache)?;
    let request = VaultRequest::decode(&bytes)?;
    let response = service.handle(&caller, request, unix_time()?);
    let bytes = response.encode()?;
    // The response gets its own budget so a slow store operation cannot make
    // the vault drop a reply it has already committed.
    write_frame(stream, &bytes, IoBudget::new(IPC_FRAME_IO_TIMEOUT))
}

fn caller_identity(stream: &BytePipe, cache: &CallerIdentityCache) -> VaultResult<CallerIdentity> {
    let process_id = stream
        .client_process_id()
        .map_err(|error| io_error("read named-pipe client PID", &error))?;
    let client_sid = client_sid(stream)?;
    if client_sid != current_process_sid()? {
        return Err(VaultError::AuthorizationRequired);
    }
    let (executable, start_time) = process_executable(process_id)?;
    // Everything below reads one opened handle rather than the path, so the
    // digest, the size, and the timestamp all describe the same image even if
    // the peer executes something else meanwhile.
    let mut opened = File::open(&executable)
        .map_err(|error| VaultError::Protocol(format!("could not open executable: {error}")))?;
    let metadata = opened
        .metadata()
        .map_err(|error| VaultError::Protocol(format!("could not inspect executable: {error}")))?;
    let modified = metadata
        .modified()
        .and_then(|time| {
            time.duration_since(UNIX_EPOCH)
                .map_err(|error| io::Error::other(error.to_string()))
        })
        .map_err(|error| VaultError::Protocol(format!("could not inspect executable: {error}")))?;
    let cache_key = format!(
        "{client_sid}:{process_id}:{start_time}:{}:{}:{}:{}",
        executable.display(),
        metadata.len(),
        modified.as_secs(),
        modified.subsec_nanos()
    );
    let identity = cache.resolve(cache_key, || {
        CallerIdentity::new(
            CallerPlatform::Windows,
            client_sid,
            executable.to_string_lossy().into_owned(),
            hash_open_file(&mut opened, &executable)?,
            None,
        )
    })?;
    // The peer PID was captured when the pipe was accepted and a PID is
    // reusable, so the process must still be the one that connected.
    if process_executable(process_id)?.1 != start_time {
        return Err(VaultError::AuthorizationRequired);
    }
    Ok(identity)
}

fn client_sid(stream: &BytePipe) -> VaultResult<String> {
    let _impersonation = stream
        .impersonate_client()
        .map_err(|error| io_error("impersonate named-pipe client", &error))?;
    let token = open_current_thread_token()?;
    token
        .user()
        .and_then(|sid| sid.to_string())
        .map_err(|error| VaultError::Protocol(format!("could not read client SID: {error}")))
}

fn current_process_sid() -> VaultResult<String> {
    OwnedToken::from_current_process(TOKEN_QUERY)
        .and_then(|token| token.user())
        .and_then(|sid| sid.to_string())
        .map_err(|error| VaultError::Protocol(format!("could not read process SID: {error}")))
}

fn open_current_thread_token() -> VaultResult<OwnedToken> {
    // SAFETY: `GetCurrentThread` yields the calling thread's pseudo-handle.
    // `OpenThreadToken` initializes `handle` on success with an exclusively
    // owned token handle, which is immediately transferred to `OwnedToken`.
    unsafe {
        let mut handle = HANDLE::default();
        OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &raw mut handle).map_err(
            |error| {
                VaultError::Protocol(format!(
                    "could not open impersonated thread token {}: {error}",
                    GetCurrentThreadId()
                ))
            },
        )?;
        Ok(OwnedToken::new(handle))
    }
}

/// Resolve one process without enumerating the machine.
///
/// `System::new_all()` scanned every process and all hardware on every
/// incoming connection, and it ran before the caller-identity cache could
/// avoid it, so a cache hit paid for it too.
fn process_executable(process_id: u32) -> VaultResult<(PathBuf, u64)> {
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

fn same_user_security_descriptor() -> VaultResult<SecurityDescriptor> {
    let sddl = format!(
        "D:P(A;;GA;;;{})(A;;GA;;;SY)(A;;GA;;;BA)",
        current_process_sid()?
    );
    let sddl = U16CString::from_str(sddl)
        .map_err(|error| VaultError::Protocol(format!("invalid pipe DACL: {error}")))?;
    SecurityDescriptor::deserialize(&sddl)
        .map_err(|error| io_error("create same-user pipe DACL", &error))
}

fn validate_options(options: &WindowsVaultOptions) -> VaultResult<()> {
    validate_pipe_name(&options.pipe_name)?;
    if options.poll_interval.is_zero() || options.poll_interval > Duration::from_secs(1) {
        return Err(VaultError::Protocol(
            "Windows vault poll interval must be between zero and one second".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "hardware")]
    use crate::{
        GrantPermission, UnsealLeasePolicy, Vault, VaultAction, VaultId, VaultResponseBody,
        WireSecret, WireSecretAddress, vault::VaultStore,
    };

    #[test]
    fn pipe_names_are_local_and_factorseal_scoped() {
        assert!(validate_pipe_name(r"\\.\pipe\factorseal").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\factorseal-device-id").is_ok());
        assert!(validate_pipe_name(r"\\server\pipe\factorseal-device-id").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\other-device-id").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\factorseal-nested\name").is_err());
    }

    #[test]
    fn offline_identity_uses_the_process_sid_and_digest() {
        let identity = windows_caller_identity_for_executable(
            std::env::current_exe().expect("current executable must have a path"),
        )
        .unwrap();
        assert_eq!(identity.platform(), CallerPlatform::Windows);
        assert_eq!(identity.user_id(), current_process_sid().unwrap());
        assert_ne!(identity.executable_digest(), &[0; 32]);
    }

    #[test]
    #[cfg(feature = "hardware")]
    fn lifecycle_monitor_registers_with_windows() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("factorseal");
        let unsealed = Vault::create_for_test(&root).unwrap();
        let store = VaultStore::open(root, unsealed).unwrap();
        let service = Arc::new(
            VaultService::new(store, unix_time().unwrap(), UnsealLeasePolicy::default()).unwrap(),
        );
        let stopping = Arc::new(AtomicBool::new(false));
        let monitor = WindowsLifecycleMonitor::new(service, Arc::clone(&stopping)).unwrap();
        assert!(!stopping.load(Ordering::Acquire));
        drop(monitor);
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

        let options = WindowsVaultOptions {
            pipe_name: format!(r"\\.\pipe\factorseal-test-{}", VaultId::random().unwrap()),
            poll_interval: Duration::from_millis(5),
            install_signal_handler: false,
            install_lifecycle_monitor: false,
        };
        assert!(serve_windows_vault(&service, &options).is_err());
        assert!(
            service.expire_if_needed(unix_time().unwrap()).unwrap(),
            "an error exit must still discard the unwrapped keys"
        );
    }

    #[test]
    fn production_options_require_lifecycle_monitoring() {
        let options = WindowsVaultOptions::new(r"\\.\pipe\factorseal-device-id");
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
            windows_caller_identity_for_executable(std::env::current_exe().unwrap()).unwrap();
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

        let pipe_name = format!(r"\\.\pipe\factorseal-test-{}", VaultId::random().unwrap());
        let options = WindowsVaultOptions {
            pipe_name: pipe_name.clone(),
            poll_interval: Duration::from_millis(5),
            install_signal_handler: false,
            install_lifecycle_monitor: false,
        };
        let server_service = Arc::clone(&service);
        let server = std::thread::spawn(move || serve_windows_vault(&server_service, &options));
        let client = WindowsVaultClient::new(pipe_name);
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
        client: &WindowsVaultClient,
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
            "the Windows vault is still serving but unreachable: {last:?}"
        );
        panic!("the Windows vault thread exited during startup: {last:?}");
    }

    #[test]
    fn lifecycle_messages_cover_suspend_shutdown_logout_and_lock() {
        assert!(lifecycle_message_requires_lock(
            WM_POWERBROADCAST,
            PBT_APMSUSPEND as usize
        ));
        assert!(lifecycle_message_requires_lock(WM_QUERYENDSESSION, 0));
        assert!(lifecycle_message_requires_lock(WM_ENDSESSION, 1));
        assert!(!lifecycle_message_requires_lock(WM_ENDSESSION, 0));
        for event in [
            WTS_SESSION_LOCK,
            WTS_SESSION_LOGOFF,
            WTS_CONSOLE_DISCONNECT,
            WTS_REMOTE_DISCONNECT,
        ] {
            assert!(lifecycle_message_requires_lock(
                WM_WTSSESSION_CHANGE,
                event as usize
            ));
        }
    }
}

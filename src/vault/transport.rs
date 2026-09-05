//! Transport pieces shared by every platform adapter and native client.
//!
//! Framing, bounded blocking I/O, executable hashing, and the Unix socket
//! lifecycle were copied across five modules. A change to the frame bound had
//! to be repeated six times to stay consistent, and applying it to only some
//! of them was silently inconsistent.

#[cfg(feature = "vault")]
use std::fs::File;
use std::io::{self, Read, Write};
#[cfg(feature = "vault")]
use std::path::Path;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[cfg(feature = "vault")]
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{VaultError, VaultResult};
#[cfg(feature = "vault-client")]
use super::{VaultRequest, VaultResponse};

pub(crate) const MAX_FRAME_BYTES: usize = 1024 * 1024;
#[cfg(feature = "vault")]
pub(crate) const MAX_ACTIVE_CONNECTIONS: usize = 8;

/// Bounds one frame exchanged with a peer that has already been accepted.
/// This is deliberately short so a connected client cannot pin the
/// single-user vault with a partial frame.
#[cfg(feature = "vault")]
pub(crate) const IPC_FRAME_IO_TIMEOUT: Duration = Duration::from_millis(500);

/// Allows the server to authenticate a previously unseen executable and
/// complete a local store operation before the client abandons the response.
/// This remains a finite fail-closed bound for direct Rust clients such as the
/// provider compiled into SecretSpec.
#[cfg(feature = "vault-client")]
pub(crate) const IPC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

const IO_RETRY_INTERVAL: Duration = Duration::from_millis(2);

/// One deadline covering every partial read and write of a whole frame.
///
/// Starting a fresh deadline inside each helper let one peer spend the bound
/// once per partial transfer instead of once per frame.
#[derive(Clone, Copy)]
pub(crate) struct IoBudget<'a> {
    deadline: Instant,
    cancelled: Option<&'a std::sync::atomic::AtomicBool>,
}

impl IoBudget<'_> {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            // An unrepresentable deadline fails closed rather than panicking.
            deadline: Instant::now()
                .checked_add(timeout)
                .unwrap_or_else(Instant::now),
            cancelled: None,
        }
    }

    fn exhausted(self) -> bool {
        Instant::now() >= self.deadline
            || self
                .cancelled
                .is_some_and(|flag| flag.load(Ordering::Acquire))
    }

    #[cfg(feature = "vault")]
    pub(crate) fn capped(mut self, deadline: Option<Instant>) -> Self {
        if let Some(deadline) = deadline {
            self.deadline = self.deadline.min(deadline);
        }
        self
    }

    fn expired(operation: &'static str) -> io::Error {
        io::Error::new(
            io::ErrorKind::TimedOut,
            format!("local IPC {operation} deadline exceeded"),
        )
    }
}

#[cfg(feature = "vault")]
impl<'a> IoBudget<'a> {
    pub(crate) fn cancelled_by(mut self, flag: Option<&'a std::sync::atomic::AtomicBool>) -> Self {
        self.cancelled = flag;
        self
    }
}

/// Send one authenticated-client request and validate its matching response.
///
/// Platform clients deliberately keep their native endpoint connection and
/// caller authentication separate, but their framed request exchange must
/// have identical timeout and response-binding behavior.
#[cfg(feature = "vault-client")]
pub(crate) fn exchange_request(
    stream: &mut (impl Read + Write),
    request: &VaultRequest,
) -> VaultResult<VaultResponse> {
    // One budget covers the whole exchange, including the server's first-use
    // authentication of this executable.
    let budget = IoBudget::new(IPC_RESPONSE_TIMEOUT);
    let request_id = request.request_id();
    let request = request.encode()?;
    write_frame(stream, &request, budget)?;
    let response = read_frame(stream, budget)?;
    let response = VaultResponse::decode(&response)?;
    if response.request_id() != request_id {
        return Err(VaultError::Protocol(
            "vault response request ID does not match".to_owned(),
        ));
    }
    Ok(response)
}

/// Read one length-prefixed frame within `budget`.
pub(crate) fn read_frame(
    reader: &mut impl Read,
    budget: IoBudget,
) -> VaultResult<Zeroizing<Vec<u8>>> {
    let mut length = [0_u8; 4];
    read_exact_bounded(reader, &mut length, budget)
        .map_err(|error| VaultError::Protocol(format!("could not read frame length: {error}")))?;
    let length = usize::try_from(u32::from_be_bytes(length))
        .map_err(|_| VaultError::Protocol("frame length does not fit in memory".to_owned()))?;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(VaultError::Protocol(
            "frame length is outside the supported range".to_owned(),
        ));
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    read_exact_bounded(reader, &mut bytes, budget)
        .map_err(|error| VaultError::Protocol(format!("could not read frame: {error}")))?;
    Ok(bytes)
}

/// Write one length-prefixed frame within `budget`.
pub(crate) fn write_frame(
    writer: &mut impl Write,
    bytes: &[u8],
    budget: IoBudget,
) -> VaultResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(VaultError::Protocol(
            "frame length is outside the supported range".to_owned(),
        ));
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| VaultError::Protocol("frame is too large".to_owned()))?;
    write_all_bounded(writer, &length.to_be_bytes(), budget)
        .and_then(|()| write_all_bounded(writer, bytes, budget))
        .map_err(|error| VaultError::Protocol(format!("could not write frame: {error}")))
}

fn read_exact_bounded(
    reader: &mut impl Read,
    mut bytes: &mut [u8],
    budget: IoBudget,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if budget.exhausted() {
            return Err(IoBudget::expired("read"));
        }
        match reader.read(bytes) {
            // A nonblocking Windows pipe reports "nothing to read yet" as a
            // successful zero-byte read rather than WouldBlock, and a pipe
            // that has actually closed surfaces as an error instead. Treating
            // that as end of file made the vault drop every connection the
            // instant it accepted one, before the client had written. On Unix
            // a zero-byte read is end of file and has to stay one.
            Ok(0) if cfg!(windows) => {
                if budget.exhausted() {
                    return Err(IoBudget::expired("read"));
                }
                std::thread::sleep(IO_RETRY_INTERVAL);
            }
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
            Ok(read) => bytes = &mut bytes[read..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if budget.exhausted() {
                    return Err(IoBudget::expired("read"));
                }
                std::thread::sleep(IO_RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn write_all_bounded(
    writer: &mut impl Write,
    mut bytes: &[u8],
    budget: IoBudget,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if budget.exhausted() {
            return Err(IoBudget::expired("write"));
        }
        match writer.write(bytes) {
            // Same asymmetry as the read side: a nonblocking Windows pipe
            // reports a full buffer as a successful zero-byte write.
            Ok(0) if cfg!(windows) => {
                if budget.exhausted() {
                    return Err(IoBudget::expired("write"));
                }
                std::thread::sleep(IO_RETRY_INTERVAL);
            }
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero)),
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if budget.exhausted() {
                    return Err(IoBudget::expired("write"));
                }
                std::thread::sleep(IO_RETRY_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
    writer.flush()
}

/// Digest an already opened executable, so the bytes hashed are the bytes of
/// the file the caller resolved rather than whatever the path names later.
#[cfg(feature = "vault")]
pub(crate) fn hash_open_file(file: &mut File, path: &Path) -> VaultResult<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = Zeroizing::new(vec![0_u8; 64 * 1024]);
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| path_io_error(path, &error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest.finalize().into())
}

#[cfg(feature = "vault")]
pub(crate) fn hash_file(path: &Path) -> VaultResult<[u8; 32]> {
    let mut file = File::open(path).map_err(|error| path_io_error(path, &error))?;
    hash_open_file(&mut file, path)
}

#[cfg(feature = "vault")]
pub(crate) fn unix_time() -> VaultResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| VaultError::Protocol(error.to_string()))
}

#[cfg(feature = "vault")]
pub(crate) fn path_io_error(path: &Path, error: &io::Error) -> VaultError {
    VaultError::Protocol(format!("I/O error for `{}`: {error}", path.display()))
}

#[cfg(target_os = "windows")]
pub(crate) fn pipe_io_error(operation: &str, error: &io::Error) -> VaultError {
    VaultError::Protocol(format!("Windows IPC could not {operation}: {error}"))
}

/// Same-user Unix socket lifecycle shared by the Linux and macOS servers.
#[cfg(all(feature = "vault", any(target_os = "linux", target_os = "macos")))]
pub(crate) mod unix_socket {
    use std::fs;
    use std::io;
    use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Duration;

    use nix::unistd::getuid;

    use super::{
        IPC_FRAME_IO_TIMEOUT, IoBudget, MAX_ACTIVE_CONNECTIONS, path_io_error, read_frame,
        unix_time, write_frame,
    };
    use crate::vault::{CallerIdentity, VaultError, VaultRequest, VaultResult, VaultService};

    struct ActiveConnection<'a>(&'a AtomicUsize);

    impl Drop for ActiveConnection<'_> {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Bind a private nonblocking listener and retain ownership of removing
    /// its socket path when the server exits.
    pub(crate) fn bind_listener(path: &Path) -> VaultResult<(UnixListener, SocketGuard)> {
        prepare_socket_path(path)?;
        let listener = UnixListener::bind(path).map_err(|error| path_io_error(path, &error))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| path_io_error(path, &error))?;
        listener
            .set_nonblocking(true)
            .map_err(|error| path_io_error(path, &error))?;
        Ok((listener, SocketGuard::new(path.to_owned())))
    }

    pub(crate) fn install_shutdown_signal_handler(stopping: &Arc<AtomicBool>) -> VaultResult<()> {
        let signal_stopping = Arc::clone(stopping);
        ctrlc::set_handler(move || signal_stopping.store(true, Ordering::Release)).map_err(
            |error| VaultError::Protocol(format!("could not install signal handler: {error}")),
        )
    }

    /// Poll one nonblocking Unix listener until shutdown, lifecycle policy, or
    /// lease expiry asks the platform server to stop.
    pub(crate) fn accept_until_sealed(
        service: &VaultService,
        listener: &UnixListener,
        stopping: &AtomicBool,
        socket_path: &Path,
        poll_interval: Duration,
        mut poll_lifecycle: impl FnMut() -> VaultResult<bool>,
        authenticate: impl Fn(&UnixStream) -> VaultResult<CallerIdentity> + Sync,
    ) -> VaultResult<()> {
        let active = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            while !stopping.load(Ordering::Acquire) {
                if poll_lifecycle()? || service.expire_if_needed(unix_time()?)? {
                    service.seal()?;
                    return Ok(());
                }
                if active.load(Ordering::Acquire) >= MAX_ACTIVE_CONNECTIONS {
                    std::thread::sleep(poll_interval);
                    continue;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        active.fetch_add(1, Ordering::AcqRel);
                        let active = &active;
                        let authenticate = &authenticate;
                        if let Err(error) = std::thread::Builder::new()
                            .name("factorseal-ipc".to_owned())
                            .spawn_scoped(scope, move || {
                                let _active = ActiveConnection(active);
                                // A malformed or disconnected client must not
                                // terminate the per-user vault.
                                let _ = handle_connection(service, &mut stream, authenticate);
                            })
                        {
                            active.fetch_sub(1, Ordering::AcqRel);
                            return Err(VaultError::Protocol(format!(
                                "could not start bounded IPC worker: {error}"
                            )));
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(poll_interval);
                    }
                    Err(error) => return Err(path_io_error(socket_path, &error)),
                }
            }
            service.seal()?;
            Ok(())
        })
    }

    /// Exchange one request with an accepted Unix peer after platform-native
    /// authentication supplies its caller identity.
    pub(crate) fn handle_connection(
        service: &VaultService,
        stream: &mut UnixStream,
        authenticate: impl FnOnce(&UnixStream) -> VaultResult<CallerIdentity>,
    ) -> VaultResult<()> {
        stream.set_nonblocking(true).map_err(|error| {
            VaultError::Protocol(format!("could not bound client I/O: {error}"))
        })?;
        let caller = authenticate(stream)?;
        let bytes = read_frame(stream, IoBudget::new(IPC_FRAME_IO_TIMEOUT))?;
        let request = VaultRequest::decode(&bytes)?;
        let response = service.handle(&caller, request, unix_time()?);
        let bytes = response.encode()?;
        // Give delivery its own I/O budget, never beyond the authority that
        // authorized this result. A committed write can outlive its reply.
        write_frame(
            stream,
            &bytes,
            IoBudget::new(IPC_FRAME_IO_TIMEOUT)
                .capped(response.delivery_deadline)
                .cancelled_by(response.delivery_cancelled.as_deref()),
        )
    }

    /// Reject a configuration the transport cannot make private before it
    /// binds anything.
    pub(crate) fn validate_socket_options(
        platform: &str,
        socket_path: &Path,
        poll_interval: Duration,
    ) -> VaultResult<()> {
        if poll_interval.is_zero() || poll_interval > Duration::from_secs(1) {
            return Err(VaultError::Protocol(format!(
                "{platform} vault poll interval must be between zero and one second"
            )));
        }
        let parent = socket_path.parent().ok_or_else(|| {
            VaultError::Protocol(format!("{platform} vault socket path has no parent"))
        })?;
        let metadata =
            fs::symlink_metadata(parent).map_err(|error| path_io_error(parent, &error))?;
        let mode = metadata.permissions().mode() & 0o777;
        if !metadata.file_type().is_dir()
            || metadata.uid() != getuid().as_raw()
            || mode & 0o077 != 0
        {
            return Err(VaultError::Protocol(format!(
                "{platform} vault socket parent must be a private directory owned by this user"
            )));
        }
        Ok(())
    }

    /// Remove a stale socket left by a previous vault, refusing to replace a
    /// live vault or a path this user does not own.
    fn prepare_socket_path(path: &Path) -> VaultResult<()> {
        match UnixStream::connect(path) {
            Ok(_) => Err(VaultError::Protocol(
                "another Factorseal vault is already accepting connections".to_owned(),
            )),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(_) => {
                let metadata =
                    fs::symlink_metadata(path).map_err(|error| path_io_error(path, &error))?;
                if !metadata.file_type().is_socket() || metadata.uid() != getuid().as_raw() {
                    return Err(VaultError::Protocol(
                        "refusing to replace a non-socket or foreign-owned path".to_owned(),
                    ));
                }
                fs::remove_file(path).map_err(|error| path_io_error(path, &error))
            }
        }
    }

    pub(crate) struct SocketGuard(PathBuf);

    impl SocketGuard {
        const fn new(path: PathBuf) -> Self {
            Self(path)
        }
    }

    impl Drop for SocketGuard {
        fn drop(&mut self) {
            if let Ok(metadata) = fs::symlink_metadata(&self.0)
                && metadata.file_type().is_socket()
                && metadata.uid() == getuid().as_raw()
            {
                let _ = fs::remove_file(&self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(feature = "vault-client", feature = "vault"))]
    use crate::vault::MAX_PERMISSION_WAIT_MS;
    #[cfg(feature = "vault-client")]
    use crate::vault::{VaultAction, VaultResponseBody};
    #[cfg(feature = "vault-client")]
    use std::io::Cursor;

    #[cfg(feature = "vault-client")]
    struct ScriptedStream {
        received: Cursor<Vec<u8>>,
        sent: Vec<u8>,
    }

    #[cfg(feature = "vault-client")]
    impl Read for ScriptedStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.received.read(bytes)
        }
    }

    #[cfg(feature = "vault-client")]
    impl Write for ScriptedStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.sent.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// The server hashes a previously unseen executable before it answers,
    /// which is why the client budget is not the frame budget.
    #[test]
    #[cfg(all(feature = "vault", feature = "vault-client"))]
    fn a_client_deadline_outlasts_first_use_caller_authentication() {
        assert!(IPC_RESPONSE_TIMEOUT >= IPC_FRAME_IO_TIMEOUT * 4);
        assert!(IPC_RESPONSE_TIMEOUT > Duration::from_millis(MAX_PERMISSION_WAIT_MS));
    }

    #[test]
    fn an_exhausted_budget_never_blocks() {
        let mut empty: &[u8] = &[];
        let budget = IoBudget::new(Duration::ZERO);
        assert!(read_frame(&mut empty, budget).is_err());

        let mut sink = Vec::new();
        assert!(write_frame(&mut sink, b"frame", budget).is_err());
        assert!(sink.is_empty());
    }

    /// The Windows arm above must not have turned a closed reader into a
    /// stall on the platforms where a zero-byte read really is end of file.
    #[test]
    #[cfg(unix)]
    fn a_closed_reader_is_end_of_file_rather_than_a_stall() {
        let mut closed: &[u8] = &[];
        assert!(read_frame(&mut closed, IoBudget::new(Duration::from_mins(1))).is_err());
    }

    #[test]
    fn framing_round_trips_and_rejects_lengths_outside_the_range() {
        // Framing is what is under test, so this budget only has to be large
        // enough not to interfere with in-memory transfers.
        let budget = IoBudget::new(Duration::from_mins(1));
        let mut wire = Vec::new();
        write_frame(&mut wire, b"request", budget).unwrap();
        assert_eq!(
            read_frame(&mut wire.as_slice(), budget).unwrap().as_slice(),
            b"request"
        );

        assert!(write_frame(&mut Vec::new(), b"", budget).is_err());
        let oversized = (u32::try_from(MAX_FRAME_BYTES).unwrap() + 1).to_be_bytes();
        assert!(read_frame(&mut oversized.as_slice(), budget).is_err());
    }

    #[test]
    #[cfg(feature = "vault-client")]
    fn shared_exchange_preserves_the_request_response_binding() {
        let request = VaultRequest::new(VaultAction::Status).unwrap();
        let response = VaultResponse::success(request.request_id(), VaultResponseBody::Stored);
        let mut received = Vec::new();
        write_frame(
            &mut received,
            &response.encode().unwrap(),
            IoBudget::new(Duration::from_secs(1)),
        )
        .unwrap();
        let mut stream = ScriptedStream {
            received: Cursor::new(received),
            sent: Vec::new(),
        };

        let response = exchange_request(&mut stream, &request).unwrap();

        assert_eq!(response.request_id(), request.request_id());
        let request_bytes = read_frame(
            &mut stream.sent.as_slice(),
            IoBudget::new(Duration::from_secs(1)),
        )
        .unwrap();
        assert_eq!(
            VaultRequest::decode(&request_bytes).unwrap().request_id(),
            request.request_id()
        );
    }
}

//! Browser/Desktop RPC uses the existing native peer-authentication routines.
use super::CallerIdentityCache;
#[cfg(target_os = "linux")]
use super::linux::{caller_identity, linux_caller_identity_for_executable as identity};
#[cfg(target_os = "macos")]
use super::macos::{caller_identity, macos_caller_identity_for_executable as identity};
#[cfg(target_os = "windows")]
use super::windows::{caller_identity, windows_caller_identity_for_executable as identity};
use crate::browser::{MAX_FRAME, Request, Response};
use crate::security::{
    LockedBytes,
    bounded::{IoBudget, read_exact_bounded, write_all_bounded},
};
use crate::{VaultError, VaultResult};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
fn error(e: impl std::fmt::Display) -> VaultError {
    VaultError::Protocol(format!("browser transport: {e}"))
}
#[must_use]
pub fn endpoint(root: &Path) -> PathBuf {
    #[cfg(unix)]
    {
        root.join("browser.sock")
    }
    #[cfg(target_os = "windows")]
    {
        use sha2::{Digest, Sha256};
        let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        PathBuf::from(format!(
            r"\\.\pipe\factorseal-browser-{}",
            hex::encode(Sha256::digest(
                root.as_os_str().to_string_lossy().as_bytes()
            ))
        ))
    }
}
fn read(stream: &mut impl Read) -> VaultResult<LockedBytes> {
    let budget = IoBudget::new(Duration::from_secs(2));
    let mut length = [0; 4];
    read_exact_bounded(stream, &mut length, budget).map_err(error)?;
    let n = u32::from_be_bytes(length) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(error("invalid frame length"));
    }
    let mut bytes = LockedBytes::zeroed(n)?;
    read_exact_bounded(stream, &mut bytes, budget).map_err(error)?;
    Ok(bytes)
}
fn write(stream: &mut impl Write, bytes: &[u8]) -> VaultResult<()> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME {
        return Err(error("invalid frame length"));
    }
    let budget = IoBudget::new(Duration::from_secs(2));
    write_all_bounded(
        stream,
        &u32::try_from(bytes.len()).map_err(error)?.to_be_bytes(),
        budget,
    )
    .map_err(error)?;
    write_all_bounded(stream, bytes, budget).map_err(error)
}
/// Pins the installed Desktop identity and reuses the transport's validated
/// executable cache; polling must not hash both binaries for every message.
pub struct Client {
    root: PathBuf,
    #[cfg(unix)]
    expected: super::CallerIdentity,
    #[cfg(unix)]
    cache: CallerIdentityCache,
}
impl Client {
    pub fn new(root: &Path, desktop: &Path) -> VaultResult<Self> {
        #[cfg(target_os = "windows")]
        let _ = desktop;
        Ok(Self {
            root: root.to_path_buf(),
            #[cfg(unix)]
            expected: identity(desktop)?,
            #[cfg(unix)]
            cache: CallerIdentityCache::default(),
        })
    }
    pub fn exchange(&self, request: &Request) -> VaultResult<Response> {
        #[cfg(unix)]
        let mut stream = {
            let stream =
                std::os::unix::net::UnixStream::connect(endpoint(&self.root)).map_err(error)?;
            if caller_identity(&stream, &self.cache)? != self.expected {
                return Err(VaultError::AuthorizationRequired);
            }
            stream.set_nonblocking(true).map_err(error)?;
            stream
        };
        #[cfg(target_os = "windows")]
        let (mut stream, _server_guard) = {
            let pipe = super::windows_client::connect_pipe(&endpoint(&self.root).to_string_lossy())
                .map_err(error)?;
            let guard = super::windows_client::authenticate_server(&pipe)?;
            (pipe, guard)
        };
        let bytes = crate::security::memory::serialize_locked(request, MAX_FRAME).map_err(error)?;
        write(&mut stream, &bytes)?;
        serde_json::from_slice(&read(&mut stream)?).map_err(error)
    }
}
/// Spawn a bounded server. Desktop lifetime owns its listener thread.
pub fn serve(
    root: &Path,
    bridge: &Path,
    handler: &(dyn Fn(Request) -> Response + Send + Sync),
) -> VaultResult<()> {
    let expected = identity(bridge)?;
    let cache = CallerIdentityCache::default();
    let path = endpoint(root);
    #[cfg(unix)]
    let (listener, _guard) = {
        super::transport::unix_socket::validate_socket_options(
            "browser",
            &path,
            Duration::from_millis(50),
        )?;
        super::transport::unix_socket::bind_listener(&path)?
    };
    #[cfg(target_os = "windows")]
    let listener = super::windows::private_listener(&path)?;
    // Requests are short polling RPCs. A single server bounds work and memory.
    loop {
        #[cfg(unix)]
        let accepted = listener.accept().map(|(s, _)| s);
        #[cfg(target_os = "windows")]
        let accepted = listener.accept();
        match accepted {
            Ok(mut stream) => {
                let result = (|| -> VaultResult<()> {
                    stream.set_nonblocking(true).map_err(error)?;
                    #[cfg(unix)]
                    if caller_identity(&stream, &cache)? != expected {
                        return Err(VaultError::AuthorizationRequired);
                    }
                    let bytes = read(&mut stream)?;
                    #[cfg(target_os = "windows")]
                    if caller_identity(&stream, &cache)? != expected {
                        return Err(VaultError::AuthorizationRequired);
                    }
                    let request = serde_json::from_slice(&bytes).map_err(error)?;
                    let response = handler(request);
                    let encoded = crate::security::memory::serialize_locked(&response, MAX_FRAME)
                        .map_err(error)?;
                    write(&mut stream, &encoded)
                })();
                let _ = result;
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(error(e)),
        }
    }
}

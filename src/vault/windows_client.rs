#![allow(unsafe_code)]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::time::{Duration, Instant};

use nt_token::OwnedToken;
use windows::Win32::Foundation::{
    ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_LISTENING, GENERIC_READ, GENERIC_WRITE, HANDLE,
    HLOCAL, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetSecurityInfo, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    READ_CONTROL, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
};
use windows::Win32::System::Pipes::{
    GetNamedPipeServerProcessId, PIPE_NOWAIT, SetNamedPipeHandleState,
};
use windows::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

use super::transport::{exchange_request, pipe_io_error as io_error};
use super::{InstallationId, VaultClient, VaultError, VaultRequest, VaultResponse, VaultResult};

const PIPE_PREFIX: &str = r"\\.\pipe\factorseal-";

/// Synchronous PIPE_NOWAIT handle. Opening it ourselves sets identification-
/// only SQOS atomically and avoids a dependency reopening it with weaker SQOS.
struct ClientPipe(File);

fn nonblocking_error(error: io::Error) -> io::Error {
    if error.raw_os_error().is_some_and(|code| {
        [ERROR_NO_DATA.0, ERROR_PIPE_BUSY.0, ERROR_PIPE_LISTENING.0].contains(&code.cast_unsigned())
    }) {
        io::Error::from(io::ErrorKind::WouldBlock)
    } else {
        error
    }
}

impl Read for ClientPipe {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.read(bytes).map_err(nonblocking_error)
    }
}

impl Write for ClientPipe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes).map_err(nonblocking_error)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn connect_pipe(path: &str) -> io::Result<ClientPipe> {
    let deadline = Instant::now() + super::transport::IPC_RESPONSE_TIMEOUT;
    loop {
        let opened = OpenOptions::new()
            .access_mode(GENERIC_READ.0 | GENERIC_WRITE.0 | READ_CONTROL.0)
            .custom_flags(SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0)
            .open(path);
        match opened {
            Ok(file) => {
                // SAFETY: the file owns this connected local pipe; mode is a
                // live u32. No data is sent before peer authentication.
                unsafe {
                    SetNamedPipeHandleState(
                        HANDLE(file.as_raw_handle()),
                        Some(&PIPE_NOWAIT),
                        None,
                        None,
                    )
                }
                .map_err(|error| io::Error::other(error.to_string()))?;
                return Ok(ClientPipe(file));
            }
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY.0.cast_signed()) => {
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Keep the process handle alive through the exchange. Pipe ownership is
/// checked independently, so PID reuse cannot turn another user's pipe into
/// a same-user endpoint.
fn authenticate_server(pipe: &ClientPipe) -> VaultResult<OwnedHandle> {
    let expected = OwnedToken::from_current_process(TOKEN_QUERY)
        .and_then(|token| token.user())
        .map_err(server_authentication_error)?;
    authenticate_server_sid(pipe, &expected)
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "Result::map_err consumes the native error"
)]
fn server_authentication_error(error: windows::core::Error) -> VaultError {
    VaultError::Protocol(format!("could not authenticate named-pipe server: {error}"))
}

fn authenticate_server_sid(
    pipe: &ClientPipe,
    expected: &nt_token::Sid,
) -> VaultResult<OwnedHandle> {
    let failed = server_authentication_error;
    let handle = HANDLE(pipe.0.as_raw_handle());
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: output pointers refer to live locals. GetSecurityInfo allocates
    // the returned descriptor; the SID is copied before LocalFree releases it.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    };
    if status.0 != 0 {
        return Err(VaultError::AuthorizationRequired);
    }
    let mut owner_text = windows::core::PWSTR::null();
    let owner = unsafe { ConvertSidToStringSidW(owner, &raw mut owner_text) }
        .map_err(failed)
        .and_then(|()| {
            unsafe { owner_text.to_string() }.map_err(|_| VaultError::AuthorizationRequired)
        });
    unsafe { LocalFree(Some(HLOCAL(owner_text.0.cast()))) };
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    if owner? != expected.to_string().map_err(failed)? {
        return Err(VaultError::AuthorizationRequired);
    }
    let mut pid = 0;
    // SAFETY: connected pipe and out-pointer are valid. Each successful
    // handle allocation is immediately transferred to an owning RAII type.
    let process = unsafe {
        GetNamedPipeServerProcessId(handle, &raw mut pid).map_err(failed)?;
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(failed)?;
        OwnedHandle::from_raw_handle(process.0)
    };
    let token = unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(HANDLE(process.as_raw_handle()), TOKEN_QUERY, &raw mut token)
            .map_err(failed)?;
        OwnedToken::new(token)
    };
    if &token.user().map_err(failed)? != expected {
        return Err(VaultError::AuthorizationRequired);
    }
    Ok(process)
}

/// Derive the native endpoint for one Windows installation.
///
/// Named pipes live outside the filesystem, so the installation ID provides
/// the same per-installation routing that `<root>/factorseal.sock` provides on
/// Unix.
#[must_use]
pub fn default_windows_pipe_name(installation_id: InstallationId) -> String {
    format!("{PIPE_PREFIX}{installation_id}")
}

/// Lightweight native client for the Factorseal Windows vault.
#[derive(Clone, Debug)]
pub struct WindowsVaultClient {
    pipe_name: String,
}

impl WindowsVaultClient {
    #[must_use]
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
        }
    }

    /// Connect to the default named pipe derived for `installation_id`.
    #[must_use]
    pub fn for_installation(installation_id: InstallationId) -> Self {
        Self::new(default_windows_pipe_name(installation_id))
    }

    fn request_inner(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        validate_pipe_name(&self.pipe_name)?;
        let mut stream = connect_pipe(&self.pipe_name).map_err(|error| {
            // Distinguish "nothing is listening" from a genuine transport
            // failure, so a caller can tell a sealed vault apart from a broken
            // one.
            match error.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    VaultError::AgentUnreachable(self.pipe_name.clone())
                }
                _ => io_error("connect to named pipe", &error),
            }
        })?;
        let _server = authenticate_server(&stream)?;
        exchange_request(&mut stream, request)
    }
}

impl VaultClient for WindowsVaultClient {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        self.request_inner(request)
    }
}

pub(super) fn validate_pipe_name(pipe_name: &str) -> VaultResult<()> {
    if !pipe_name.starts_with(PIPE_PREFIX)
        || pipe_name.len() == PIPE_PREFIX.len()
        || pipe_name[PIPE_PREFIX.len()..].contains(['\\', '/'])
    {
        return Err(VaultError::Protocol(
            "Windows pipe must be a local Factorseal pipe name".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "vault")]
    #[test]
    fn connected_server_owner_is_checked_without_sending_request_bytes() {
        use interprocess::os::windows::named_pipe::{PipeListenerOptions, pipe_mode};
        use interprocess::os::windows::security_descriptor::SecurityDescriptor;
        use std::path::Path;
        let sid = OwnedToken::from_current_process(TOKEN_QUERY)
            .unwrap()
            .user()
            .unwrap();
        let sddl = widestring::U16CString::from_str(format!("O:{sid}D:P(A;;GA;;;{sid})")).unwrap();
        let descriptor = SecurityDescriptor::deserialize(&sddl).unwrap();
        let name = format!("{PIPE_PREFIX}security-test-{}", std::process::id());
        let listener = PipeListenerOptions::new()
            .path(Path::new(&name))
            .nonblocking(true)
            .accept_remote(false)
            .security_descriptor(Some(descriptor))
            .create_duplex::<pipe_mode::Bytes>()
            .unwrap();
        let mut client = connect_pipe(&name).unwrap();
        let mut server = listener.accept().unwrap();
        authenticate_server(&client).unwrap();
        let other = nt_token::Sid::parse("S-1-5-21-1-2-3-9999").unwrap();
        assert!(matches!(
            authenticate_server_sid(&client, &other),
            Err(VaultError::AuthorizationRequired)
        ));
        let read = server.read(&mut [0; 1]);
        assert!(
            matches!(read, Ok(0))
                || read.is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock)
        );
        client.write_all(b"x").unwrap();
        server.read_exact(&mut [0; 1]).unwrap();
        let _impersonation = server.impersonate_client().unwrap();
        // SAFETY: OpenAsSelf permits querying the identification-level token;
        // the freshly allocated handle is immediately owned by OwnedToken.
        let token = unsafe {
            let mut token = HANDLE::default();
            windows::Win32::System::Threading::OpenThreadToken(
                windows::Win32::System::Threading::GetCurrentThread(),
                TOKEN_QUERY,
                true,
                &raw mut token,
            )
            .unwrap();
            OwnedToken::new(token)
        };
        assert_eq!(token.user().unwrap(), sid);
        assert_eq!(
            token.impersonation_level().unwrap(),
            windows::Win32::Security::SecurityIdentification
        );
    }

    #[test]
    fn default_pipe_name_is_stable_and_installation_scoped() {
        let first = InstallationId::from_bytes([0x11; 16]);
        let second = InstallationId::from_bytes([0x22; 16]);

        assert_eq!(
            default_windows_pipe_name(first),
            default_windows_pipe_name(first)
        );
        assert_ne!(
            default_windows_pipe_name(first),
            default_windows_pipe_name(second)
        );
        assert!(validate_pipe_name(&default_windows_pipe_name(first)).is_ok());
    }

    #[test]
    fn bare_and_non_local_pipe_names_are_rejected() {
        assert!(validate_pipe_name(r"\\.\pipe\factorseal").is_err());
        assert!(validate_pipe_name(r"\\server\pipe\factorseal-device-id").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\other-device-id").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\factorseal-nested\name").is_err());
    }
}

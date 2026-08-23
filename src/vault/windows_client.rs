use std::path::Path;

use interprocess::os::windows::named_pipe::{DuplexPipeStream, pipe_mode};

use super::transport::{exchange_request, pipe_io_error as io_error};
use super::{VaultClient, VaultError, VaultId, VaultRequest, VaultResponse, VaultResult};

const PIPE_PREFIX: &str = r"\\.\pipe\factorseal-";
type BytePipe = DuplexPipeStream<pipe_mode::Bytes>;

/// Derive the native endpoint for one Windows vault.
///
/// Named pipes live outside the filesystem, so the vault ID provides the same
/// per-vault routing that `<root>/factorseal.sock` provides on Unix.
#[must_use]
pub fn default_windows_pipe_name(vault_id: VaultId) -> String {
    format!("{PIPE_PREFIX}{vault_id}")
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

    /// Connect to the default named pipe derived for `vault_id`.
    #[must_use]
    pub fn for_vault(vault_id: VaultId) -> Self {
        Self::new(default_windows_pipe_name(vault_id))
    }

    fn request_inner(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        validate_pipe_name(&self.pipe_name)?;
        let mut stream =
            BytePipe::connect_by_path(Path::new(&self.pipe_name)).map_err(|error| {
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
        stream
            .set_nonblocking(true)
            .map_err(|error| io_error("bound named-pipe I/O", &error))?;
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

    #[test]
    fn default_pipe_name_is_stable_and_vault_scoped() {
        let first = VaultId::from_bytes([0x11; 16]);
        let second = VaultId::from_bytes([0x22; 16]);

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

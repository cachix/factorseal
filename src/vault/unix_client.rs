//! Native client for the Factorseal Unix-socket vault service.
//!
//! Linux and macOS speak the same framed protocol over the same socket type,
//! so one implementation serves both; each target re-exports it under the name
//! of the transport it talks to.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use super::transport::exchange_request;
use super::{VaultClient, VaultError, VaultRequest, VaultResponse, VaultResult};

/// Lightweight native client for the Factorseal per-user vault.
#[derive(Clone, Debug)]
pub struct UnixVaultClient {
    socket_path: PathBuf,
}

impl UnixVaultClient {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    fn request_inner(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|error| connect_error(&self.socket_path, &error))?;
        stream
            .set_nonblocking(true)
            .map_err(|error| io_error(&self.socket_path, &error))?;
        exchange_request(&mut stream, request)
    }
}

impl VaultClient for UnixVaultClient {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        self.request_inner(request)
    }
}

/// Distinguish "nothing is listening" from a genuine transport failure, so a
/// caller can tell a sealed vault apart from a broken one.
fn connect_error(path: &Path, error: &io::Error) -> VaultError {
    match error.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused => {
            VaultError::AgentUnreachable(path.display().to_string())
        }
        _ => io_error(path, error),
    }
}

fn io_error(path: &Path, error: &io::Error) -> VaultError {
    VaultError::Protocol(format!("I/O error for `{}`: {error}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{VaultAction, VaultRequest};

    #[test]
    fn an_absent_socket_reports_that_no_agent_is_listening() {
        let directory = tempfile::tempdir().unwrap();
        let client = UnixVaultClient::new(directory.path().join("factorseal.sock"));
        let request = VaultRequest::new(VaultAction::Status).unwrap();
        let error = client.request(&request).unwrap_err();
        assert!(
            matches!(error, VaultError::AgentUnreachable(_)),
            "an absent socket must not look like a transport failure, got: {error:?}"
        );
    }

    #[test]
    fn a_stale_socket_file_reports_that_no_agent_is_listening() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("factorseal.sock");
        // What a crashed agent leaves behind: binding does not unlink on drop,
        // so the socket outlives the listener with nothing accepting on it.
        drop(std::os::unix::net::UnixListener::bind(&socket).unwrap());
        let client = UnixVaultClient::new(&socket);
        let request = VaultRequest::new(VaultAction::Status).unwrap();
        let error = client.request(&request).unwrap_err();
        assert!(
            matches!(error, VaultError::AgentUnreachable(_)),
            "a stale socket file must not look like a transport failure, got: {error:?}"
        );
    }
}

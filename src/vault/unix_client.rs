//! Native client for the Factorseal Unix-socket vault service.
//!
//! Linux and macOS speak the same framed protocol over the same socket type,
//! so one implementation serves both; each target re-exports it under the name
//! of the transport it talks to.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use super::transport::{IPC_RESPONSE_TIMEOUT, IoBudget, read_frame, write_frame};
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
            .map_err(|error| io_error(&self.socket_path, &error))?;
        stream
            .set_nonblocking(true)
            .map_err(|error| io_error(&self.socket_path, &error))?;
        // One budget covers the whole exchange, including the server's
        // first-use authentication of this executable.
        let budget = IoBudget::new(IPC_RESPONSE_TIMEOUT);
        let request_id = request.request_id();
        let request = request.encode()?;
        write_frame(&mut stream, &request, budget)?;
        let response = read_frame(&mut stream, budget)?;
        let response = VaultResponse::decode(&response)?;
        if response.request_id() != request_id {
            return Err(VaultError::Protocol(
                "vault response request ID does not match".to_owned(),
            ));
        }
        Ok(response)
    }
}

impl VaultClient for UnixVaultClient {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        self.request_inner(request)
    }
}

fn io_error(path: &Path, error: &io::Error) -> VaultError {
    VaultError::Protocol(format!("I/O error for `{}`: {error}", path.display()))
}

use std::path::Path;

use interprocess::os::windows::named_pipe::{DuplexPipeStream, pipe_mode};

use super::transport::{
    IPC_RESPONSE_TIMEOUT, IoBudget, pipe_io_error as io_error, read_frame, write_frame,
};
use super::{VaultClient, VaultError, VaultRequest, VaultResponse, VaultResult};

const PIPE_PREFIX: &str = r"\\.\pipe\factorseal-";
const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\factorseal";
type BytePipe = DuplexPipeStream<pipe_mode::Bytes>;

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

impl VaultClient for WindowsVaultClient {
    fn request(&self, request: &VaultRequest) -> VaultResult<VaultResponse> {
        self.request_inner(request)
    }
}

fn validate_pipe_name(pipe_name: &str) -> VaultResult<()> {
    if pipe_name != DEFAULT_PIPE_NAME
        && (!pipe_name.starts_with(PIPE_PREFIX)
            || pipe_name.len() == PIPE_PREFIX.len()
            || pipe_name[PIPE_PREFIX.len()..].contains(['\\', '/']))
    {
        return Err(VaultError::Protocol(
            "Windows pipe must be a local Factorseal pipe name".to_owned(),
        ));
    }
    Ok(())
}

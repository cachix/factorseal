//! Native client for the Factorseal Unix-socket agents.
//!
//! Linux and macOS speak the same framed protocol over the same socket type,
//! so one implementation serves both; each target re-exports it under the name
//! of the transport it talks to.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use super::transport::{IPC_RESPONSE_TIMEOUT, IoBudget, read_frame, write_frame};
use super::{AgentClient, AgentError, AgentRequest, AgentResponse, AgentResult};

/// Lightweight native client for the Factorseal per-user agent.
#[derive(Clone, Debug)]
pub struct UnixAgentClient {
    socket_path: PathBuf,
}

impl UnixAgentClient {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: socket_path.into(),
        }
    }

    fn request_inner(&self, request: &AgentRequest) -> AgentResult<AgentResponse> {
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
        let response = AgentResponse::decode(&response)?;
        if response.request_id() != request_id {
            return Err(AgentError::Protocol(
                "agent response request ID does not match".to_owned(),
            ));
        }
        Ok(response)
    }
}

impl AgentClient for UnixAgentClient {
    fn request(&self, request: &AgentRequest) -> AgentResult<AgentResponse> {
        self.request_inner(request)
    }
}

fn io_error(path: &Path, error: &io::Error) -> AgentError {
    AgentError::Protocol(format!("I/O error for `{}`: {error}", path.display()))
}

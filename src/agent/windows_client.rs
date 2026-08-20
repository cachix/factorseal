use std::path::Path;

use interprocess::os::windows::named_pipe::{DuplexPipeStream, pipe_mode};

use super::transport::{
    IPC_RESPONSE_TIMEOUT, IoBudget, pipe_io_error as io_error, read_frame, write_frame,
};
use super::{AgentClient, AgentError, AgentRequest, AgentResponse, AgentResult};

const PIPE_PREFIX: &str = r"\\.\pipe\factorseal-";
type BytePipe = DuplexPipeStream<pipe_mode::Bytes>;

/// Lightweight native client for the Factorseal Windows agent.
#[derive(Clone, Debug)]
pub struct WindowsAgentClient {
    pipe_name: String,
}

impl WindowsAgentClient {
    #[must_use]
    pub fn new(pipe_name: impl Into<String>) -> Self {
        Self {
            pipe_name: pipe_name.into(),
        }
    }

    fn request_inner(&self, request: &AgentRequest) -> AgentResult<AgentResponse> {
        validate_pipe_name(&self.pipe_name)?;
        let mut stream = BytePipe::connect_by_path(Path::new(&self.pipe_name))
            .map_err(|error| io_error("connect to named pipe", &error))?;
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
        let response = AgentResponse::decode(&response)?;
        if response.request_id() != request_id {
            return Err(AgentError::Protocol(
                "agent response request ID does not match".to_owned(),
            ));
        }
        Ok(response)
    }
}

impl AgentClient for WindowsAgentClient {
    fn request(&self, request: &AgentRequest) -> AgentResult<AgentResponse> {
        self.request_inner(request)
    }
}

fn validate_pipe_name(pipe_name: &str) -> AgentResult<()> {
    if !pipe_name.starts_with(PIPE_PREFIX)
        || pipe_name.len() == PIPE_PREFIX.len()
        || pipe_name[PIPE_PREFIX.len()..].contains(['\\', '/'])
    {
        return Err(AgentError::Protocol(
            "Windows pipe must be a local Factorseal pipe name".to_owned(),
        ));
    }
    Ok(())
}

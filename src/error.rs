/// Internal errors produced by shared cryptographic and hardware adapters.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no supported hardware security backend is available: {0}")]
    HardwareUnavailable(String),

    #[error("hardware security operation failed: {0}")]
    Hardware(String),

    #[error("cryptographic authentication failed")]
    Authentication,

    #[error("random-number generation failed: {0}")]
    Random(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<getrandom::Error> for Error {
    fn from(error: getrandom::Error) -> Self {
        Self::Random(error.to_string())
    }
}

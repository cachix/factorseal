/// Internal errors produced by shared cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum Error {
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

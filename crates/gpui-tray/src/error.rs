/// The result type returned by gpui-tray operations.
pub type Result<T> = std::result::Result<T, Error>;

/// An error produced while creating or updating a tray icon.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The current target does not have a tray backend.
    #[error("system tray is unsupported on this platform")]
    UnsupportedPlatform,

    /// An operation was attempted from a thread other than the creating thread.
    #[error("tray operation must run on the GPUI thread")]
    WrongThread,

    /// Pixel data or dimensions supplied for an icon were invalid.
    #[error("invalid icon: {0}")]
    InvalidIcon(String),

    /// A GPUI menu item has no meaningful tray representation.
    #[error("unsupported GPUI menu item: {0}")]
    UnsupportedMenuItem(&'static str),

    /// A native platform operation failed.
    #[error("native tray error: {0}")]
    Native(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A native platform operation failed without exposing a typed source.
    #[error("native tray error: {0}")]
    NativeMessage(String),

    /// The tray has already been closed.
    #[error("tray has been closed")]
    Closed,
}

impl Error {
    pub(crate) fn native(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Native(Box::new(error))
    }

    pub(crate) fn native_message(message: impl Into<String>) -> Self {
        Self::NativeMessage(message.into())
    }
}

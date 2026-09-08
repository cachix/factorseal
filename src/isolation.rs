//! Private helper processes. The public visibility serves the packaged helper
//! entry points; this is not an application-facing protocol or grant surface.

mod codec;
pub mod parser;
mod process;
mod sandbox;
#[cfg(windows)]
pub(crate) mod windows;

#[cfg(feature = "personal-sync-network")]
pub mod network;

pub use process::helper_executable;

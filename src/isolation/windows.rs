//! Windows helpers enter a less-privileged AppContainer at creation. Only a
//! connected private pipe is inherited, and an owning job kills the complete
//! helper on failure or parent exit. No writable AppContainer profile is made.
#![allow(unsafe_code)]

mod access;
#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
mod channel;

#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
pub(super) use channel::Channel;
#[cfg(feature = "personal-sync-network")]
pub(super) use channel::stdio_channel;

use std::io;
#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
use windows::Win32::Foundation::HANDLE;

#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
mod launch;
#[cfg(any(feature = "key-protection", feature = "transfer"))]
pub(crate) use access::current_app_sid;
#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
pub(super) use launch::{Owner, spawn};

pub(super) fn verify(network: bool) -> io::Result<()> {
    access::verify(network)
}

#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
fn raw(handle: &OwnedHandle) -> HANDLE {
    HANDLE(handle.as_raw_handle())
}
#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
fn owned(handle: HANDLE) -> io::Result<OwnedHandle> {
    if handle.is_invalid() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: callers transfer unique ownership of newly returned Win32 handles.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
}
#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
fn at(stage: &str, error: &io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{stage}: {error}"))
}
fn error(error: windows::core::Error) -> io::Error {
    let code = error.code().0.cast_unsigned();
    if code & 0xffff_0000 == 0x8007_0000 {
        io::Error::from_raw_os_error((error.code().0) & 0xffff)
    } else {
        io::Error::other(error)
    }
}

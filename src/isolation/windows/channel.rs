use super::{error, owned, raw};
#[cfg(feature = "personal-sync-network")]
use std::time::Duration;
use std::{
    io::{self, Read, Write},
    os::windows::io::OwnedHandle,
};
use windows::Win32::{
    Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, GENERIC_READ,
        GENERIC_WRITE, HANDLE, HLOCAL, LocalFree,
    },
    Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    },
    Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_SHARE_MODE,
        OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_ANONYMOUS, SECURITY_SQOS_PRESENT,
        WriteFile,
    },
    System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    },
};
#[cfg(feature = "personal-sync-network")]
use windows::Win32::{
    System::Console::{GetStdHandle, STD_INPUT_HANDLE},
    System::Pipes::{PIPE_WAIT, PeekNamedPipe, SetNamedPipeHandleState},
};
use windows::core::HSTRING;

pub(crate) struct Channel {
    handle: OwnedHandle,
}
#[cfg(feature = "personal-sync-network")]
impl Channel {
    pub(crate) fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            handle: self.handle.try_clone()?,
        })
    }
    pub(crate) fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
        let mode = if enabled { PIPE_NOWAIT } else { PIPE_WAIT };
        unsafe { SetNamedPipeHandleState(raw(&self.handle), Some(&raw const mode), None, None) }
            .map_err(error)
    }
    pub(crate) fn wait_readable(&self) -> io::Result<()> {
        loop {
            let mut available = 0;
            match unsafe {
                PeekNamedPipe(
                    raw(&self.handle),
                    None,
                    0,
                    None,
                    Some(&raw mut available),
                    None,
                )
            }
            .map_err(error)
            {
                Ok(()) if available == 0 => std::thread::sleep(Duration::from_millis(2)),
                Ok(()) => return Ok(()),
                Err(error) if matches!(error.raw_os_error(), Some(109 | 233)) => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }
}
impl Read for Channel {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut count = 0;
        match unsafe { ReadFile(raw(&self.handle), Some(bytes), Some(&raw mut count), None) }
            .map_err(error)
        {
            Ok(()) => Ok(count as usize),
            Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA.0.cast_signed()) => {
                Err(io::ErrorKind::WouldBlock.into())
            }
            // A closed peer is end of file, as Read requires: read_to_end
            // callers rely on it. No data yet is WouldBlock above, so unlike
            // the vault's client pipes a zero-byte read here is never a stall.
            Err(error) if matches!(error.raw_os_error(), Some(109 | 233)) => Ok(0),
            Err(error) => Err(error),
        }
    }
}
impl Write for Channel {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        // A nonblocking named-pipe write larger than its quota can repeatedly
        // succeed with zero bytes, even while the peer is draining it. Keep
        // each write below our 64 KiB pipe capacity; write_all and the shared
        // frame deadline handle the remainder and temporary backpressure.
        let bytes = &bytes[..bytes.len().min(16 * 1024)];
        let mut count = 0;
        unsafe { WriteFile(raw(&self.handle), Some(bytes), Some(&raw mut count), None) }
            .map_err(error)?;
        if count == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(count as usize)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn pair() -> io::Result<(Channel, OwnedHandle)> {
    let mut nonce = [0_u8; 24];
    getrandom::fill(&mut nonce).map_err(|error| io::Error::other(error.to_string()))?;
    let name = HSTRING::from(format!(
        r"\\.\pipe\LOCAL\factorseal-helper-{}",
        hex::encode(nonce)
    ));
    let user = nt_token::OwnedToken::from_current_process(TOKEN_QUERY)
        .map_err(io::Error::other)?
        .user()
        .map_err(io::Error::other)?
        .to_string()
        .map_err(io::Error::other)?;
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(format!("D:P(A;;GA;;;{user})")),
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(error)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("attributes"),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let server = unsafe {
        CreateNamedPipeW(
            &name,
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            Some(&raw const attributes),
        )
    };
    let server = owned(server);
    unsafe {
        LocalFree(Some(HLOCAL(descriptor.0)));
    }
    let server = server.map_err(|error| super::at("create pipe server", &error))?;
    let child = owned(
        unsafe {
            CreateFileW(
                &name,
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS,
                None,
            )
        }
        .map_err(error)
        .map_err(|error| super::at("connect pipe client", &error))?,
    )?;
    let mut inherited = HANDLE::default();
    unsafe {
        DuplicateHandle(
            windows::Win32::System::Threading::GetCurrentProcess(),
            raw(&child),
            windows::Win32::System::Threading::GetCurrentProcess(),
            &raw mut inherited,
            0,
            true,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(error)?;
    let input = owned(inherited)?;
    match unsafe { ConnectNamedPipe(raw(&server), None) }.map_err(error) {
        Ok(()) => {}
        Err(error) if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED.0.cast_signed()) => {}
        Err(error) => return Err(error),
    }
    Ok((Channel { handle: server }, input))
}

#[cfg(feature = "personal-sync-network")]
pub(crate) fn stdio_channel() -> io::Result<Channel> {
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) }.map_err(error)?;
    let mut duplicate = HANDLE::default();
    unsafe {
        DuplicateHandle(
            windows::Win32::System::Threading::GetCurrentProcess(),
            input,
            windows::Win32::System::Threading::GetCurrentProcess(),
            &raw mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(error)?;
    let channel = Channel {
        handle: owned(duplicate)?,
    };
    channel.set_nonblocking(true)?;
    Ok(channel)
}

#[cfg(all(unix, any(feature = "vault", feature = "personal-sync-network")))]
use std::process::{Child, Command, Stdio};
use std::{
    io,
    path::{Path, PathBuf},
};

#[cfg(all(any(unix, windows), feature = "personal-sync-network"))]
use crate::security::bounded::{IoBudget, read_bounded, write_bounded};
#[cfg(all(any(unix, windows), feature = "personal-sync-network"))]
use std::{
    io::{Read, Write},
    time::Duration,
};

#[cfg(all(windows, feature = "personal-sync-network"))]
pub(super) use super::windows::stdio_channel;
#[cfg(all(windows, any(feature = "vault", feature = "personal-sync-network")))]
pub(super) use super::windows::{Channel, Owner, spawn};
#[cfg(unix)]
pub(super) use std::os::unix::net::UnixStream as Channel;

/// Helpers are installed beside their host executable. Cargo test binaries
/// live one directory below the helpers built by `cargo build --bins`.
pub fn helper_executable(host: &Path, name: &str) -> io::Result<PathBuf> {
    if !matches!(name, "factorseal-parser" | "factorseal-network") {
        return Err(io::Error::other("unknown helper"));
    }
    let mut directory = host
        .parent()
        .ok_or_else(|| io::Error::other("host has no directory"))?;
    if directory.file_name().is_some_and(|name| name == "deps") {
        directory = directory
            .parent()
            .ok_or_else(|| io::Error::other("invalid build directory"))?;
    }
    let name = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    };
    let path = directory.join(name);
    // Cargo can place intermediate test executables in a separate build-dir.
    // The override exists only in unit-test builds, never shipped hosts.
    #[cfg(test)]
    let path = std::env::var_os("FACTORSEAL_TEST_HELPER_DIR").map_or(path.clone(), |directory| {
        PathBuf::from(directory).join(path.file_name().expect("helper filename"))
    });
    // Follow symlinks: packaged installs such as Nix profiles expose the
    // helper beside the host through a link farm. The target still has to
    // be a regular file rather than a FIFO or device.
    let metadata = std::fs::metadata(&path)?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::other(
            "helper must be an installed regular executable",
        ));
    }
    Ok(path)
}

#[cfg(all(unix, any(feature = "vault", feature = "personal-sync-network")))]
pub(super) struct Owner {
    child: Child,
}
#[cfg(all(unix, any(feature = "vault", feature = "personal-sync-network")))]
impl Owner {
    pub(super) fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
#[cfg(all(unix, any(feature = "vault", feature = "personal-sync-network")))]
impl Drop for Owner {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(all(unix, any(feature = "vault", feature = "personal-sync-network")))]
pub(super) fn spawn(path: &Path, _: Option<&Path>) -> io::Result<(Owner, Channel)> {
    use std::os::fd::OwnedFd;
    let (parent, child) = std::os::unix::net::UnixStream::pair()?;
    let input: OwnedFd = child.try_clone()?.into();
    let output: OwnedFd = child.into();
    let diagnostics = if cfg!(test) {
        Stdio::inherit()
    } else {
        Stdio::null()
    };
    let child = Command::new(path)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(diagnostics)
        .spawn()?;
    let owner = Owner { child };
    parent.set_nonblocking(true)?;
    Ok((owner, parent))
}

#[cfg(all(unix, feature = "personal-sync-network"))]
pub(super) fn stdio_channel() -> io::Result<std::os::unix::net::UnixStream> {
    use std::os::fd::BorrowedFd;
    // SAFETY: the packaged network entry point is launched with a private
    // Unix socket as stdin. Cloning gives the returned stream its own owner.
    #[allow(unsafe_code)]
    let fd = unsafe { BorrowedFd::borrow_raw(0) }.try_clone_to_owned()?;
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    Ok(stream)
}

/// A helper channel with one budget over a whole frame. The retry loops are
/// the vault transport's; on Unix each read first sleeps in poll until the
/// socket is readable or the budget ends instead of retrying on an interval.
#[cfg(all(any(unix, windows), feature = "personal-sync-network"))]
struct Deadline<'a> {
    stream: &'a mut Channel,
    budget: IoBudget<'a>,
}

#[cfg(all(any(unix, windows), feature = "personal-sync-network"))]
impl<'a> Deadline<'a> {
    fn new(stream: &'a mut Channel) -> Self {
        Self {
            stream,
            budget: IoBudget::new(Duration::from_secs(30)),
        }
    }

    #[cfg(unix)]
    fn wait_readable(&self) -> io::Result<()> {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::fd::AsFd;
        loop {
            let timeout =
                PollTimeout::try_from(self.budget.remaining()).unwrap_or(PollTimeout::MAX);
            match poll(
                &mut [PollFd::new(self.stream.as_fd(), PollFlags::POLLIN)],
                timeout,
            ) {
                Ok(0) => return Err(IoBudget::expired("read")),
                Ok(_) => return Ok(()),
                Err(nix::errno::Errno::EINTR) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// Block until the bytes arrive: tests assert on frames, never on elapsed time.
#[cfg(all(test, any(unix, windows), feature = "personal-sync-network"))]
pub(super) fn read_exact_for_test(stream: &mut Channel, bytes: &mut [u8]) -> io::Result<()> {
    stream.set_nonblocking(false)?;
    let result = stream.read_exact(bytes);
    stream.set_nonblocking(true)?;
    result
}
#[cfg(all(any(unix, windows), feature = "personal-sync-network"))]
impl Read for Deadline<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        #[cfg(unix)]
        self.wait_readable()?;
        read_bounded(self.stream, bytes, self.budget)
    }
}
#[cfg(all(any(unix, windows), feature = "personal-sync-network"))]
impl Write for Deadline<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        write_bounded(self.stream, bytes, self.budget)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(all(any(unix, windows), feature = "personal-sync-network"))]
pub(super) fn send(
    stream: &mut Channel,
    message: &impl serde::Serialize,
    maximum: usize,
) -> io::Result<()> {
    super::codec::send(&mut Deadline::new(stream), message, maximum)
}

#[cfg(all(any(unix, windows), feature = "personal-sync-network"))]
pub(super) fn receive<T: serde::de::DeserializeOwned>(
    stream: &mut Channel,
    maximum: usize,
) -> io::Result<T> {
    // Idle is not a partial frame. Once any bytes arrive the complete frame
    // shares one finite deadline, independent of the number of short reads.
    #[cfg(unix)]
    {
        use nix::poll::{PollFd, PollFlags, poll};
        use std::os::fd::AsFd;
        loop {
            match poll(
                &mut [PollFd::new(stream.as_fd(), PollFlags::POLLIN)],
                1000_u16,
            ) {
                Ok(0) | Err(nix::errno::Errno::EINTR) => {}
                Ok(_) => break,
                Err(error) => return Err(error.into()),
            }
        }
    }
    #[cfg(windows)]
    stream.wait_readable()?;
    let bytes = super::codec::read(&mut Deadline::new(stream), maximum)?;
    super::codec::decode(&bytes, maximum)
}

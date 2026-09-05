use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use zeroize::Zeroizing;

fn open_regular(path: &Path, private: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        // NONBLOCK ensures a FIFO cannot block before fstat rejects it.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0);
        options.share_mode(1); // Allow readers, deny concurrent writers/deletion.
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("input must be a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
            return Err(io::Error::other("reparse-point inputs are not accepted"));
        }
        if private {
            super::windows::validate_private_file(&file)?;
        }
    }
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::MetadataExt as _;
        // SAFETY: geteuid has no arguments or memory preconditions.
        #[allow(unsafe_code)]
        let uid = unsafe { libc::geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "input must be owned by the current user and inaccessible to group or other users",
            ));
        }
    }
    Ok(file)
}

fn read_file(path: &Path, maximum: u64, private: bool) -> io::Result<Zeroizing<Vec<u8>>> {
    let file = open_regular(path, private)?;
    if file.metadata()?.len() > maximum {
        return Err(io::Error::other("input exceeds its size limit"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        return Err(io::Error::other("input exceeds its size limit"));
    }
    Ok(bytes)
}

/// Read a bounded regular file from the same descriptor that was validated.
pub fn read_regular_file(path: &Path, maximum: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    read_file(path, maximum, false)
}

/// Read a bounded, current-user-only password/passphrase file without following
/// a final symlink or Windows reparse point.
pub fn read_private_file(path: &Path, maximum: u64) -> io::Result<Zeroizing<Vec<u8>>> {
    read_file(path, maximum, true)
}

/// Publish a private file by renaming a private temporary file in its directory.
pub fn write_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    #[cfg(not(windows))]
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(windows)]
    let mut temporary =
        tempfile::Builder::new().make_in(parent, super::windows::create_private_file)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    #[test]
    fn private_reads_reject_links_permissions_and_oversize_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("password");
        write_private_file(&path, b"secret").unwrap();
        assert_eq!(&**read_private_file(&path, 6).unwrap(), b"secret");
        assert!(read_private_file(&path, 5).is_err());
        let link = dir.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(read_private_file(&link, 6).is_err());
        assert!(read_regular_file(dir.path(), 6).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_file(&path, 6).is_err());
        write_private_file(&path, b"replacement").unwrap();
        assert_eq!(&**read_private_file(&path, 11).unwrap(), b"replacement");
    }
}

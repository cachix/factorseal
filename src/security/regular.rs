use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

/// Open and validate the same handle, without following a final link or
/// blocking on a FIFO before its type can be checked.
pub(crate) fn open_regular(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // Win32 FILE_FLAG_OPEN_REPARSE_POINT. Keep this usable by the portable
        // vault-store feature without requiring the optional Windows bindings.
        options.custom_flags(0x0020_0000);
        options.share_mode(1); // FILE_SHARE_READ; deny writers and deletion.
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::other("input must be a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.nlink() != 1 {
            return Err(io::Error::other("hard-linked inputs are not accepted"));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        use std::os::windows::io::AsRawHandle as _;
        use windows::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle},
        };
        // Win32 FILE_ATTRIBUTE_REPARSE_POINT, including non-symlink reparse tags.
        if metadata.file_attributes() & 0x0400 != 0 {
            return Err(io::Error::other("reparse-point inputs are not accepted"));
        }
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: the borrowed handle and output buffer remain live.
        #[allow(unsafe_code)]
        unsafe { GetFileInformationByHandle(HANDLE(file.as_raw_handle()), &raw mut information) }
            .map_err(io::Error::other)?;
        if information.nNumberOfLinks != 1 {
            return Err(io::Error::other("hard-linked inputs are not accepted"));
        }
    }
    Ok(file)
}

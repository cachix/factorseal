//! Process, password, and file protections shared by product entry points.

#[cfg(feature = "key-protection")]
mod password;
#[cfg(feature = "key-protection")]
pub use password::validate_new_password;

#[cfg(feature = "transfer")]
mod files;
#[cfg(feature = "transfer")]
pub use files::{read_private_file, read_regular_file, write_private_file};

#[cfg(all(windows, any(feature = "transfer", feature = "key-protection")))]
pub(crate) mod windows;

/// Disable Unix core files before accepting secrets. Windows requires a
/// deployment-specific dump policy; this does not claim to configure one.
pub fn disable_core_dumps() -> std::io::Result<()> {
    #[cfg(unix)]
    {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: the pointer refers to a live, correctly sized rlimit.
        #[allow(unsafe_code)]
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const limit) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Harden a dedicated key owner before it receives factors or opens keys.
/// Linux IPC clients must remain dumpable for peer executable authentication.
pub fn harden_key_owner() -> std::io::Result<()> {
    disable_core_dumps()?;
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes an integer and no pointer arguments.
        #[allow(unsafe_code)]
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

//! Process, password, and file protections shared by product entry points.

pub mod events;
#[cfg(any(feature = "key-protection", feature = "vault-store"))]
pub(crate) mod memory;

#[cfg(any(
    feature = "transfer",
    feature = "key-protection",
    feature = "vault-client",
    feature = "vault-store"
))]
pub(crate) mod regular;

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

/// Disable Unix core files and WER heap collection before accepting secrets.
/// Administrator-configured or third-party dumps need deployment controls.
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
    #[cfg(windows)]
    {
        // WER is process-local. This excludes heap collection by WER, not
        // administrator-configured full dumps or third-party dump tools.
        #[allow(unsafe_code)]
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn WerSetFlags(flags: u32) -> i32;
        }
        #[allow(unsafe_code)]
        let status = unsafe { WerSetFlags(1) }; // WER_FAULT_REPORTING_FLAG_NOHEAP
        if status < 0 {
            return Err(std::io::Error::other(
                "could not disable WER heap collection",
            ));
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

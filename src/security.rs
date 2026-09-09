//! Process, password, and file protections shared by product entry points.

pub mod events;
#[cfg(any(
    feature = "transfer",
    feature = "key-protection",
    feature = "vault-client",
    feature = "vault-store"
))]
pub(crate) mod regular;

#[cfg(any(
    feature = "key-protection",
    feature = "vault-client",
    feature = "vault-store"
))]
pub(crate) mod memory;

#[cfg(any(
    feature = "key-protection",
    feature = "vault-client",
    feature = "vault-store"
))]
pub use memory::LockedBytes;

#[cfg(feature = "key-protection")]
mod password;
#[cfg(feature = "key-protection")]
pub use password::validate_new_password;

#[cfg(any(feature = "transfer", feature = "personal-sync"))]
mod files;
#[cfg(any(feature = "transfer", feature = "personal-sync"))]
pub use files::{read_private_file, read_regular_file, write_private_file};

#[cfg(all(windows, any(feature = "transfer", feature = "key-protection")))]
pub(crate) mod windows;

/// Disable Unix core files and suppress Windows Error Reporting heap collection.
/// Windows LocalDumps, external dump tools, and privileged inspection still
/// require deployment policy; WER suppression does not disable every dump.
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
        use ::windows::Win32::System::ErrorReporting::{
            WER_FAULT_REPORTING_FLAG_NOHEAP, WerGetFlags, WerSetFlags,
        };
        // SAFETY: sets a documented flag for the calling process; no pointers.
        #[allow(unsafe_code)]
        unsafe {
            let flags = WerGetFlags(::windows::Win32::System::Threading::GetCurrentProcess())
                .map_err(std::io::Error::other)?;
            WerSetFlags(flags | WER_FAULT_REPORTING_FLAG_NOHEAP)
        }
        .map_err(std::io::Error::other)?;
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

#[cfg(all(test, windows))]
mod tests {
    #[test]
    fn windows_crash_reporting_omits_heap() {
        use ::windows::Win32::System::{
            ErrorReporting::{WER_FAULT_REPORTING_FLAG_NOHEAP, WerGetFlags},
            Threading::GetCurrentProcess,
        };
        super::disable_core_dumps().unwrap();
        // SAFETY: current process pseudo-handle is valid for this query.
        #[allow(unsafe_code)]
        let flags = unsafe { WerGetFlags(GetCurrentProcess()) }.unwrap();
        assert_ne!(flags.0 & WER_FAULT_REPORTING_FLAG_NOHEAP.0, 0);
    }
}

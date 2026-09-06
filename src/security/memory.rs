//! Dedicated, guarded key allocations. There is no unlocked fallback.
//!
//! Locking and dump exclusion happen before key bytes enter the mapping.
//! Callers must still account for stack, crypto-library and hardware-API copies.
#![allow(unsafe_code)]

use std::io;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use zeroize::Zeroize;

pub(crate) struct LockedBytes<const N: usize> {
    base: NonNull<u8>,
    data: NonNull<u8>,
    page: usize,
}

// The mapping is exclusively owned and never resized. Shared borrows expose
// immutable bytes; mutation requires &mut self. No OS thread affinity exists.
unsafe impl<const N: usize> Send for LockedBytes<N> {}
unsafe impl<const N: usize> Sync for LockedBytes<N> {}

impl<const N: usize> LockedBytes<N> {
    pub(crate) fn zeroed() -> io::Result<Self> {
        Self::allocate()
            .inspect_err(|_| super::events::record(super::events::Kind::MemoryProtectionFailed))
    }

    #[cfg(unix)]
    fn allocate() -> io::Result<Self> {
        // SAFETY: sysconf takes no pointer; page size is checked before use.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
            .map_err(|_| io::Error::other("invalid system page size"))?;
        if N == 0 || N > page || page > isize::MAX as usize / 3 {
            return Err(io::Error::other("key allocation exceeds one page"));
        }
        // SAFETY: anonymous mapping, no file or existing address is involved.
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page * 3,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let base = NonNull::new(raw.cast::<u8>()).expect("mmap returned a mapping");
        // SAFETY: middle page is in the live three-page mapping.
        let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(page)) };
        let result = (|| {
            // SAFETY: both calls cover only the owned middle page.
            if unsafe {
                libc::mprotect(
                    data.as_ptr().cast(),
                    page,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            } != 0
                || unsafe { libc::mlock(data.as_ptr().cast(), page) } != 0
            {
                return Err(io::Error::last_os_error());
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                // SAFETY: exclude only this allocation, never allocator-shared pages.
                if unsafe { libc::madvise(data.as_ptr().cast(), page, libc::MADV_DONTDUMP) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            #[cfg(target_os = "linux")]
            if unsafe { libc::madvise(data.as_ptr().cast(), page, libc::MADV_WIPEONFORK) } != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { base, data, page })
        })();
        if result.is_err() {
            // No secrets have entered the mapping. Unmapping also releases locks.
            unsafe {
                libc::munmap(base.as_ptr().cast(), page * 3);
            }
        }
        result
    }

    #[cfg(windows)]
    fn allocate() -> io::Result<Self> {
        use windows::Win32::System::{
            ErrorReporting::WerRegisterExcludedMemoryBlock,
            Memory::{
                MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc,
                VirtualFree, VirtualLock,
            },
            SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        };
        let mut information = SYSTEM_INFO::default();
        unsafe {
            GetSystemInfo(&raw mut information);
        }
        let page = information.dwPageSize as usize;
        if N == 0 || N > page {
            return Err(io::Error::other("key allocation exceeds one page"));
        }
        // Reserve guard pages, committing only the middle page.
        let raw = unsafe { VirtualAlloc(None, page * 3, MEM_RESERVE, PAGE_NOACCESS) };
        let base = NonNull::new(raw.cast::<u8>()).ok_or_else(io::Error::last_os_error)?;
        let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(page)) };
        let result = (|| {
            if unsafe { VirtualAlloc(Some(data.as_ptr().cast()), page, MEM_COMMIT, PAGE_READWRITE) }
                .is_null()
            {
                return Err(io::Error::last_os_error());
            }
            unsafe { VirtualLock(data.as_ptr().cast(), page) }.map_err(io::Error::other)?;
            unsafe { WerRegisterExcludedMemoryBlock(data.as_ptr().cast(), information.dwPageSize) }
                .map_err(io::Error::other)?;
            Ok(Self { base, data, page })
        })();
        if result.is_err() {
            unsafe {
                let _ = VirtualFree(base.as_ptr().cast(), 0, MEM_RELEASE);
            }
        }
        result
    }

    #[cfg(not(any(unix, windows)))]
    fn allocate() -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "locked key memory is unavailable",
        ))
    }
}

impl<const N: usize> Deref for LockedBytes<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        // SAFETY: the mapping holds at least N initialized bytes until Drop.
        unsafe { &*self.data.as_ptr().cast::<[u8; N]>() }
    }
}

impl<const N: usize> DerefMut for LockedBytes<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: &mut self grants exclusive access to the owned mapping.
        unsafe { &mut *self.data.as_ptr().cast::<[u8; N]>() }
    }
}

impl<const N: usize> Drop for LockedBytes<N> {
    fn drop(&mut self) {
        self.deref_mut().zeroize();
        #[cfg(unix)]
        unsafe {
            libc::munlock(self.data.as_ptr().cast(), self.page);
            libc::munmap(self.base.as_ptr().cast(), self.page * 3);
        }
        #[cfg(windows)]
        unsafe {
            use windows::Win32::System::{
                ErrorReporting::WerUnregisterExcludedMemoryBlock,
                Memory::{MEM_RELEASE, VirtualFree, VirtualUnlock},
            };
            let _ = WerUnregisterExcludedMemoryBlock(self.data.as_ptr().cast());
            let _ = VirtualUnlock(self.data.as_ptr().cast(), self.page);
            let _ = VirtualFree(self.base.as_ptr().cast(), 0, MEM_RELEASE);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_dump_policy_applies_in_child() {
        const CHILD: &str = "FACTORSEAL_TEST_PROCESS_POLICY";
        if std::env::var_os(CHILD).is_some() {
            crate::security::harden_key_owner().unwrap();
            #[cfg(unix)]
            {
                let mut limit = libc::rlimit {
                    rlim_cur: 1,
                    rlim_max: 1,
                };
                assert_eq!(
                    unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut limit) },
                    0
                );
                assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
            }
            #[cfg(windows)]
            unsafe {
                use windows::Win32::System::{
                    ErrorReporting::{WER_FAULT_REPORTING_FLAG_NOHEAP, WerGetFlags},
                    Threading::GetCurrentProcess,
                };
                let flags = WerGetFlags(GetCurrentProcess()).unwrap();
                assert_ne!(flags.0 & WER_FAULT_REPORTING_FLAG_NOHEAP.0, 0);
            }
            return;
        }
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "security::memory::tests::process_dump_policy_applies_in_child"
                ])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn locked_allocation_fails_when_lock_budget_is_zero() {
        const CHILD: &str = "FACTORSEAL_TEST_NO_MEMLOCK";
        if std::env::var_os(CHILD).is_some() {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(
                unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &raw const limit) },
                0
            );
            assert!(LockedBytes::<32>::zeroed().is_err());
            return;
        }
        assert!(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "security::memory::tests::locked_allocation_fails_when_lock_budget_is_zero"
                ])
                .env(CHILD, "1")
                .status()
                .unwrap()
                .success()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forked_children_do_not_inherit_key_bytes() {
        let mut key = LockedBytes::<32>::zeroed().unwrap();
        key.fill(0xa5);
        // The child uses only borrowed memory and _exit: no allocation,
        // locks, Rust destructors or non-async-signal-safe library calls.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let zero = key.iter().all(|byte| *byte == 0);
            unsafe {
                libc::_exit(i32::from(!zero));
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &raw mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(*key, [0xa5; 32]);
    }

    #[cfg(windows)]
    #[test]
    fn windows_keys_have_uncommitted_guard_pages() {
        use windows::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, MEMORY_BASIC_INFORMATION, VirtualQuery,
        };
        let key = LockedBytes::<32>::zeroed().unwrap();
        for (page, state) in [(0, MEM_RESERVE), (1, MEM_COMMIT), (2, MEM_RESERVE)] {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            assert_ne!(
                unsafe {
                    VirtualQuery(
                        Some(key.base.as_ptr().add(key.page * page).cast()),
                        &raw mut info,
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                },
                0
            );
            assert_eq!(info.State, state);
        }
    }

    #[test]
    fn locked_keys_are_zeroed_stable_and_wiped_before_release() {
        let mut key = LockedBytes::<64>::zeroed().unwrap();
        assert_eq!(*key, [0; 64]);
        let address = key.as_ptr();
        key.fill(0xa5);
        let mut moved = Box::new(key);
        assert_eq!(address, moved.as_ptr());
        moved.deref_mut().deref_mut().zeroize();
        assert_eq!(**moved, [0; 64]);
        assert!(LockedBytes::<0>::zeroed().is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_mapping_is_locked_and_excluded_from_dumps() {
        let key = LockedBytes::<32>::zeroed().unwrap();
        let prefix = format!("{:x}-", key.data.as_ptr() as usize);
        let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let region = maps.split(&prefix).nth(1).expect("dedicated key mapping");
        let flags = region
            .lines()
            .find(|line| line.starts_with("VmFlags:"))
            .unwrap();
        assert!(flags.split_whitespace().any(|flag| flag == "lo"));
        assert!(flags.split_whitespace().any(|flag| flag == "dd"));
    }
}

//! Dedicated, nonpageable secret allocations. No allocator page is shared with
//! unrelated objects, so unlocking one allocation cannot unlock another.
#![allow(unsafe_code)]
#![cfg_attr(
    not(any(feature = "key-protection", feature = "vault-store")),
    allow(dead_code)
)]

use crate::vault::{VaultError, VaultResult};
use std::{
    io,
    ops::{Deref, DerefMut},
    ptr::NonNull,
};
use zeroize::{Zeroize, Zeroizing};

/// A fixed-size key at the end of a locked page between inaccessible pages.
/// No Clone or serialization: duplication must explicitly allocate and lock.
/// OS/crypto input buffers and temporary copies are outside this guarantee.
pub(crate) struct LockedKey<const N: usize> {
    region: Region,
}

impl<const N: usize> LockedKey<N> {
    pub(crate) fn zeroed() -> VaultResult<Self> {
        Region::new(N)
            .and_then(|region| {
                if N > region.page {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "key must fit one page",
                    ));
                }
                Ok(Self { region })
            })
            .map_err(|error| {
                VaultError::Protection(format!("cannot allocate locked key memory: {error}"))
            })
    }

    pub(crate) fn from_slice(bytes: &[u8]) -> VaultResult<Self> {
        if bytes.len() != N {
            return Err(VaultError::Protection("invalid locked key length".into()));
        }
        let mut key = Self::zeroed()?;
        key.copy_from_slice(bytes);
        Ok(key)
    }
}

impl<const N: usize> std::fmt::Debug for LockedKey<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockedKey([REDACTED])")
    }
}

impl<const N: usize> Deref for LockedKey<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        // SAFETY: Region owns a live, readable page, N is bounded by that
        // page, and u8 arrays have alignment 1. Borrow cannot outlive self.
        unsafe {
            &*self
                .region
                .data()
                .add(self.region.page - N)
                .cast::<[u8; N]>()
        }
    }
}
impl<const N: usize> DerefMut for LockedKey<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: same bounds as Deref, with exclusive ownership of the borrow.
        unsafe {
            &mut *self
                .region
                .data()
                .add(self.region.page - N)
                .cast::<[u8; N]>()
        }
    }
}

/// Fixed-length secret bytes in locked, guarded storage. Allocation is fallible;
/// empty values allocate no pages. Sources passed by reference remain caller-owned.
/// This protects this allocation, not arbitrary copies or OS/library buffers.
#[derive(Default)]
pub struct LockedBytes {
    region: Option<Region>,
    length: usize,
}

impl LockedBytes {
    /// Allocate and lock zero-filled storage before accepting plaintext.
    pub fn zeroed(length: usize) -> VaultResult<Self> {
        let region = if length == 0 {
            None
        } else {
            Some(Region::new(length).map_err(|e| {
                VaultError::Protection(format!("cannot allocate locked secret memory: {e}"))
            })?)
        };
        Ok(Self { region, length })
    }
    /// Copy into locked memory. This does not wipe the caller's source.
    pub fn from_slice(bytes: &[u8]) -> VaultResult<Self> {
        let mut result = Self::zeroed(bytes.len())?;
        result.copy_from_slice(bytes);
        Ok(result)
    }
    /// Consume and wipe temporary input, including when locking fails.
    pub fn from_zeroizing(bytes: Zeroizing<Vec<u8>>) -> VaultResult<Self> {
        let result = Self::from_slice(&bytes);
        drop(bytes);
        result
    }
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self
    }
}
impl AsRef<[u8]> for LockedBytes {
    fn as_ref(&self) -> &[u8] {
        self
    }
}
impl AsMut<[u8]> for LockedBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        self
    }
}

impl std::fmt::Debug for LockedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockedBytes([REDACTED])")
    }
}
impl Deref for LockedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.region.as_ref().map_or(&[], |r| {
            // SAFETY: length is bounded by the committed region; trailing
            // alignment places the last byte immediately before the guard.
            unsafe { std::slice::from_raw_parts(r.data().add(r.size - self.length), self.length) }
        })
    }
}
impl DerefMut for LockedBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.region.as_mut().map_or(&mut [], |r| {
            // SAFETY: exclusive borrow of the owned region, bounded as above.
            unsafe {
                std::slice::from_raw_parts_mut(r.data().add(r.size - self.length), self.length)
            }
        })
    }
}

struct Region {
    base: NonNull<u8>,
    page: usize,
    size: usize,
    total: usize,
}
// SAFETY: the mapping is exclusively owned, never resized or aliased by an
// owning object. Mutable access requires &mut; shared access only reads bytes.
unsafe impl Send for Region {}
unsafe impl Sync for Region {}

impl Region {
    fn new(length: usize) -> io::Result<Self> {
        Self::allocate(length)
            .inspect_err(|_| super::events::record(super::events::Kind::MemoryProtectionFailed))
    }

    fn allocate(length: usize) -> io::Result<Self> {
        let page = platform::page_size()?;
        let size = length
            .checked_add(page - 1)
            .map(|n| n / page * page)
            .filter(|_| length != 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid buffer size"))?;
        let total = page
            .checked_mul(2)
            .and_then(|guards| size.checked_add(guards))
            .filter(|total| isize::try_from(*total).is_ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "buffer is too large"))?;
        let base = platform::reserve(total)?;
        let region = Self {
            base,
            page,
            size,
            total,
        };
        // No secrets have entered this mapping. On any protection/lock error,
        // release it directly: Drop's wipe requires a committed writable page.
        if let Err(error) = platform::protect_and_lock(region.data(), size) {
            platform::release(base.as_ptr(), total);
            std::mem::forget(region);
            return Err(error);
        }
        Ok(region)
    }

    fn data(&self) -> *mut u8 {
        // SAFETY: the writable region starts after the leading guard page.
        unsafe { self.base.as_ptr().add(self.page) }
    }

    fn wipe(&mut self) {
        // SAFETY: this entire region is committed and writable until release.
        unsafe { std::slice::from_raw_parts_mut(self.data(), self.size) }.zeroize();
    }
}
impl Drop for Region {
    fn drop(&mut self) {
        self.wipe();
        platform::unlock(self.data(), self.size);
        platform::release(self.base.as_ptr(), self.total);
    }
}

#[cfg(unix)]
mod platform {
    use super::{NonNull, io};
    pub(super) fn page_size() -> io::Result<usize> {
        // SAFETY: sysconf takes no pointer and queries a process-independent size.
        let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        usize::try_from(size)
            .ok()
            .filter(|s| *s > 0)
            .ok_or_else(|| io::Error::other("cannot determine page size"))
    }
    pub(super) fn reserve(size: usize) -> io::Result<NonNull<u8>> {
        // SAFETY: fresh anonymous reservation, no file or caller-owned address.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        if let Some(ptr) = NonNull::new(ptr.cast()) {
            Ok(ptr)
        } else {
            // Address zero cannot be represented by our Rust owner.
            unsafe {
                libc::munmap(ptr, size);
            }
            Err(io::Error::other("null key mapping"))
        }
    }
    pub(super) fn protect_and_lock(ptr: *mut u8, size: usize) -> io::Result<()> {
        // SAFETY: ptr/size describe the page-aligned middle of our reservation.
        unsafe {
            if libc::mprotect(ptr.cast(), size, libc::PROT_READ | libc::PROT_WRITE) != 0 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(any(target_os = "linux", target_os = "android"))]
            if libc::madvise(ptr.cast(), size, libc::MADV_DONTDUMP) != 0 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            if libc::madvise(ptr.cast(), size, libc::MADV_WIPEONFORK) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::mlock(ptr.cast(), size) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
    pub(super) fn unlock(ptr: *mut u8, size: usize) {
        // SAFETY: caller has already wiped this owned, locked page.
        unsafe {
            libc::munlock(ptr.cast(), size);
        }
    }
    pub(super) fn release(ptr: *mut u8, size: usize) {
        // SAFETY: caller owns this complete mmap reservation and relinquishes it.
        unsafe {
            libc::munmap(ptr.cast(), size);
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::{NonNull, io};
    use std::sync::Mutex;
    use windows::Win32::Foundation::ERROR_WORKING_SET_QUOTA;
    use windows::Win32::System::{
        ErrorReporting::{WerRegisterExcludedMemoryBlock, WerUnregisterExcludedMemoryBlock},
        Memory::{
            MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_NOACCESS, PAGE_READWRITE, VirtualAlloc,
            VirtualFree, VirtualLock, VirtualUnlock,
        },
        SystemInformation::{GetSystemInfo, SYSTEM_INFO},
        Threading::{GetCurrentProcess, GetProcessWorkingSetSize, SetProcessWorkingSetSize},
    };
    static WORKING_SET: Mutex<()> = Mutex::new(());
    pub(super) fn page_size() -> io::Result<usize> {
        let mut info = SYSTEM_INFO::default();
        // SAFETY: valid initialized out parameter.
        unsafe {
            GetSystemInfo(&raw mut info);
        }
        let size = info.dwPageSize as usize;
        if size == 0 {
            return Err(io::Error::other("cannot determine page size"));
        }
        Ok(size)
    }
    pub(super) fn reserve(size: usize) -> io::Result<NonNull<u8>> {
        // SAFETY: reserve a fresh inaccessible address range, no existing mapping.
        NonNull::new(unsafe { VirtualAlloc(None, size, MEM_RESERVE, PAGE_NOACCESS) }.cast())
            .ok_or_else(io::Error::last_os_error)
    }
    pub(super) fn protect_and_lock(ptr: *mut u8, size: usize) -> io::Result<()> {
        let report_size = u32::try_from(size).map_err(io::Error::other)?;
        // SAFETY: commit only the middle page of the owned reservation; guards
        // stay uncommitted. VirtualLock applies only to this committed page.
        unsafe {
            if VirtualAlloc(Some(ptr.cast()), size, MEM_COMMIT, PAGE_READWRITE).is_null() {
                return Err(io::Error::last_os_error());
            }
            lock(ptr, size)?;
            if let Err(error) = WerRegisterExcludedMemoryBlock(ptr.cast(), report_size) {
                let _ = VirtualUnlock(ptr.cast(), size);
                return Err(io::Error::other(error));
            }
            Ok(())
        }
    }
    fn lock(ptr: *mut u8, size: usize) -> io::Result<()> {
        // Small allocations need no quota change. Serialize only the retry so
        // concurrent allocations do not independently grow the working set.
        match unsafe { VirtualLock(ptr.cast(), size) } {
            Ok(()) => return Ok(()),
            Err(error) if error.code() != ERROR_WORKING_SET_QUOTA.to_hresult() => {
                return Err(io::Error::other(error));
            }
            Err(_) => {}
        }
        let _gate = WORKING_SET
            .lock()
            .map_err(|_| io::Error::other("working-set lock poisoned"))?;
        match unsafe { VirtualLock(ptr.cast(), size) } {
            Ok(()) => return Ok(()),
            Err(error) if error.code() != ERROR_WORKING_SET_QUOTA.to_hresult() => {
                return Err(io::Error::other(error));
            }
            Err(_) => {}
        }
        let (mut minimum, mut maximum) = (0, 0);
        unsafe {
            GetProcessWorkingSetSize(GetCurrentProcess(), &raw mut minimum, &raw mut maximum)
        }
        .map_err(io::Error::other)?;
        // VirtualLock's quota is the working-set minimum minus OS overhead.
        // Grow on actual exhaustion, retaining a modest allowance for that
        // overhead. Freed mappings are still wiped and VirtualUnlocked; this
        // setting records capacity, not additional pinned secret pages.
        let increased = minimum
            .checked_add(size)
            .and_then(|n| n.checked_add(1024 * 1024))
            .ok_or_else(|| io::Error::other("locked-memory quota overflow"))?;
        let maximum = maximum.max(
            increased
                .checked_add(1024 * 1024)
                .ok_or_else(|| io::Error::other("working-set quota overflow"))?,
        );
        unsafe { SetProcessWorkingSetSize(GetCurrentProcess(), increased, maximum) }
            .map_err(io::Error::other)?;
        // Locking remains mandatory, including after a successful quota change.
        unsafe { VirtualLock(ptr.cast(), size) }.map_err(io::Error::other)
    }
    pub(super) fn unlock(ptr: *mut u8, size: usize) {
        // SAFETY: caller has wiped the owned page and no references remain.
        unsafe {
            let _ = WerUnregisterExcludedMemoryBlock(ptr.cast());
            let _ = VirtualUnlock(ptr.cast(), size);
        }
    }
    pub(super) fn release(ptr: *mut u8, _size: usize) {
        // SAFETY: release the entire original reservation, not an interior page.
        unsafe {
            let _ = VirtualFree(ptr.cast(), 0, MEM_RELEASE);
        }
    }
}

#[cfg(not(any(unix, windows)))]
mod platform {
    use super::{NonNull, io};
    pub(super) fn page_size() -> io::Result<usize> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "locked memory is unavailable",
        ))
    }
    pub(super) fn reserve(_: usize) -> io::Result<NonNull<u8>> {
        unreachable!()
    }
    pub(super) fn protect_and_lock(_: *mut u8, _: usize) -> io::Result<()> {
        unreachable!()
    }
    pub(super) fn unlock(_: *mut u8, _: usize) {
        unreachable!()
    }
    pub(super) fn release(_: *mut u8, _: usize) {
        unreachable!()
    }
}

/// Serialize twice: count/bound first, then write directly to locked storage.
/// The value must have stable serialized content between the two passes.
pub(crate) fn serialize_locked(
    value: &impl serde::Serialize,
    maximum: usize,
) -> VaultResult<LockedBytes> {
    struct Counter {
        remaining: usize,
    }
    impl io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.remaining = self
                .remaining
                .checked_sub(bytes.len())
                .ok_or_else(|| io::Error::other("message exceeds configured bound"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter { remaining: maximum };
    serde_json::to_writer(&mut counter, value).map_err(|e| VaultError::Protocol(e.to_string()))?;
    let mut bytes = LockedBytes::zeroed(maximum - counter.remaining)?;
    let mut writer = bytes.as_mut();
    serde_json::to_writer(&mut writer, value).map_err(|e| VaultError::Protocol(e.to_string()))?;
    if !writer.is_empty() {
        return Err(VaultError::Protocol("serialized length changed".into()));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::{LockedBytes, LockedKey, serialize_locked};

    #[test]
    fn variable_buffers_cover_page_boundaries_and_wipe_padding() {
        let page = super::platform::page_size().unwrap();
        for length in [0, 1, page - 1, page, page + 1, 2 * page + 17] {
            let mut value = LockedBytes::zeroed(length).unwrap();
            assert_eq!(value.len(), length);
            assert!(value.iter().all(|b| *b == 0));
            value.fill(0xa5);
            let address = value.as_ptr();
            let mut moved = std::thread::spawn(move || value).join().unwrap();
            assert_eq!(moved.as_ptr(), address);
            assert!(moved.iter().all(|b| *b == 0xa5));
            assert_eq!(format!("{moved:?}"), "LockedBytes([REDACTED])");
            if let Some(region) = &mut moved.region {
                assert_eq!(
                    address as usize + length,
                    region.data() as usize + region.size
                );
                // SAFETY: test exclusively owns the entire committed mapping.
                unsafe { std::slice::from_raw_parts_mut(region.data(), region.size) }.fill(0x5a);
                region.wipe();
                // SAFETY: region remains mapped and owned after explicit wipe.
                assert!(
                    unsafe { std::slice::from_raw_parts(region.data(), region.size) }
                        .iter()
                        .all(|b| *b == 0)
                );
            }
        }
        assert!(LockedBytes::zeroed(usize::MAX).is_err());
        assert!(LockedBytes::default().is_empty());
    }

    #[test]
    fn locked_serialization_obeys_exact_byte_bounds() {
        let value = serde_json::json!({"value": "a\n🔐"});
        let expected = serde_json::to_vec(&value).unwrap();
        let encoded = serialize_locked(&value, expected.len()).unwrap();
        assert_eq!(&*encoded, expected);
        assert!(serialize_locked(&value, expected.len() - 1).is_err());
        assert!(serialize_locked(&value, 0).is_err());
    }

    #[test]
    fn keys_have_stable_distinct_storage_and_redacted_debug() {
        let key = LockedKey::<32>::from_slice(&[0x5a; 32]).unwrap();
        let address = key.as_ptr();
        let mut other = LockedKey::<32>::zeroed().unwrap();
        assert_ne!(address, other.as_ptr());
        assert_eq!(*other, [0; 32]);
        assert!(!format!("{key:?}").contains("90"));
        let moved = std::thread::spawn(move || {
            assert_eq!(*key, [0x5a; 32]);
            key
        })
        .join()
        .unwrap();
        assert_eq!(moved.as_ptr(), address);
        drop(moved);
        other.fill(0xa5);
        assert_eq!(*other, [0xa5; 32]);
        assert!(LockedKey::<0>::zeroed().is_err());
        assert!(LockedKey::<{ usize::MAX }>::zeroed().is_err());
        assert!(LockedKey::<32>::from_slice(&[0; 31]).is_err());
    }

    #[test]
    fn wipe_clears_the_entire_owned_page() {
        let mut key = LockedKey::<32>::zeroed().unwrap();
        // SAFETY: test has exclusive access to the mapping's writable page.
        unsafe { std::slice::from_raw_parts_mut(key.region.data(), key.region.page) }.fill(0xa5);
        key.region.wipe();
        // SAFETY: page remains owned and mapped until key drops.
        assert!(
            unsafe { std::slice::from_raw_parts(key.region.data(), key.region.page) }
                .iter()
                .all(|byte| *byte == 0)
        );
    }

    #[cfg(target_os = "linux")]
    fn flags(key: &LockedKey<32>) -> String {
        let address = key.as_ptr() as usize;
        let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut in_region = false;
        for line in maps.lines() {
            if let Some((start, rest)) = line.split_once('-')
                && let Some(end) = rest.split_whitespace().next()
                && let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                )
            {
                in_region = (start..end).contains(&address);
            }
            if in_region && line.starts_with("VmFlags:") {
                return line.to_owned();
            }
        }
        panic!("locked mapping absent from smaps");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_keys_are_locked_dump_excluded_and_wiped_on_fork() {
        let first = LockedKey::<32>::zeroed().unwrap();
        let second = LockedKey::<32>::zeroed().unwrap();
        for flag in ["lo", "dd", "wf"] {
            assert!(flags(&first).split_whitespace().any(|f| f == flag));
        }
        drop(first);
        assert!(flags(&second).split_whitespace().any(|f| f == "lo"));
    }

    #[cfg(unix)]
    #[test]
    fn guard_pages_and_lock_failure_are_enforced_by_the_os() {
        use std::os::unix::process::ExitStatusExt;
        for mode in [
            "underflow",
            "overflow",
            "buffer-overflow",
            "lock-limit",
            "fork",
        ] {
            if mode == "fork" && !cfg!(target_os = "linux") {
                continue;
            }
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "security::memory::tests::memory_subprocess",
                    "--nocapture",
                ])
                .env("FACTORSEAL_MEMORY_TEST_CHILD", mode)
                .output()
                .unwrap();
            if matches!(mode, "underflow" | "overflow" | "buffer-overflow") {
                assert!(
                    matches!(output.status.signal(), Some(libc::SIGSEGV | libc::SIGBUS)),
                    "{mode}: {:?}",
                    output.status
                );
            } else {
                assert!(
                    output.status.success(),
                    "{mode}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn memory_subprocess() {
        let Ok(mode) = std::env::var("FACTORSEAL_MEMORY_TEST_CHILD") else {
            return;
        };
        crate::security::disable_core_dumps().unwrap();
        if mode == "lock-limit" {
            // SAFETY: isolated child process only; do not alter the test runner.
            assert_eq!(
                unsafe {
                    libc::setrlimit(
                        libc::RLIMIT_MEMLOCK,
                        &libc::rlimit {
                            rlim_cur: 0,
                            rlim_max: 0,
                        },
                    )
                },
                0
            );
            assert!(
                LockedKey::<32>::zeroed().is_err(),
                "must not fall back to pageable memory"
            );
            assert!(LockedBytes::zeroed(1).is_err());
            assert!(
                LockedBytes::from_zeroizing(zeroize::Zeroizing::new(vec![0xa5; 8193])).is_err()
            );
            assert!(serialize_locked(&"secret", 100).is_err());
            assert!(LockedBytes::zeroed(0).unwrap().is_empty());
            return;
        }
        if mode == "buffer-overflow" {
            let bytes = LockedBytes::zeroed(super::platform::page_size().unwrap() + 17).unwrap();
            // SAFETY: deliberate guard fault in an isolated dump-disabled child.
            unsafe {
                std::ptr::write_volatile(bytes.as_ptr().add(bytes.len()).cast_mut(), 1);
            }
            panic!("trailing guard did not fault");
        }
        let key = LockedKey::<32>::from_slice(&[0xa5; 32]).unwrap();
        match mode.as_str() {
            "underflow" => {
                // SAFETY: deliberately fault in an isolated, dump-disabled process.
                unsafe {
                    std::ptr::write_volatile(key.region.data().sub(1), 1);
                }
            }
            "overflow" => {
                // SAFETY: deliberately fault in an isolated, dump-disabled process.
                unsafe {
                    std::ptr::write_volatile(key.as_ptr().add(32).cast_mut(), 1);
                }
            }
            #[cfg(target_os = "linux")]
            "fork" => {
                // SAFETY: child calls only volatile reads and async-signal-safe
                // _exit, with no Rust destructors, allocator, or runtime locks.
                unsafe {
                    let pid = libc::fork();
                    assert!(pid >= 0);
                    if pid == 0 {
                        let mut clean = true;
                        for offset in 0..32 {
                            clean &= key.as_ptr().add(offset).read_volatile() == 0;
                        }
                        libc::_exit(i32::from(!clean));
                    }
                    let mut status = 0;
                    assert_eq!(libc::waitpid(pid, &raw mut status, 0), pid);
                    assert_eq!(status, 0);
                }
                assert_eq!(*key, [0xa5; 32]);
            }
            _ => panic!("unknown subprocess mode"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_large_buffers_stay_locked_when_neighbors_drop() {
        use windows::Win32::System::{
            ProcessStatus::{K32QueryWorkingSetEx, PSAPI_WORKING_SET_EX_INFORMATION},
            Threading::GetCurrentProcess,
        };
        const CHILD: &str = "FACTORSEAL_LARGE_LOCK_TEST";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "security::memory::tests::windows_large_buffers_stay_locked_when_neighbors_drop", "--nocapture"])
                .env(CHILD, "1")
                .output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let check = |bytes: &LockedBytes| {
            for offset in [0, bytes.len() / 2, bytes.len() - 1] {
                let mut info = PSAPI_WORKING_SET_EX_INFORMATION {
                    VirtualAddress: unsafe { bytes.as_ptr().add(offset) }.cast_mut().cast(),
                    ..Default::default()
                };
                assert!(
                    unsafe {
                        K32QueryWorkingSetEx(
                            GetCurrentProcess(),
                            (&raw mut info).cast(),
                            u32::try_from(size_of_val(&info)).unwrap(),
                        )
                    }
                    .as_bool()
                );
                // PSAPI_WORKING_SET_EX_BLOCK: Valid is bit 0, Locked is bit 22.
                let flags = unsafe { info.VirtualAttributes.Flags };
                assert_eq!(flags & (1 | (1 << 22)), 1 | (1 << 22));
            }
        };
        let first = LockedBytes::zeroed(4 * 1024 * 1024).unwrap();
        let second = LockedBytes::zeroed(8 * 1024 * 1024).unwrap();
        check(&first);
        check(&second);
        drop(first);
        check(&second);
    }

    #[cfg(windows)]
    #[test]
    fn windows_mapping_has_uncommitted_guards() {
        use windows::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_READWRITE, VirtualQuery,
        };
        let key = LockedKey::<32>::zeroed().unwrap();
        for (offset, state) in [
            (0, MEM_RESERVE),
            (key.region.page, MEM_COMMIT),
            (key.region.page * 2, MEM_RESERVE),
        ] {
            let mut info = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: valid out structure; querying addresses within our reservation.
            assert_ne!(
                unsafe {
                    VirtualQuery(
                        Some(key.region.base.as_ptr().add(offset).cast()),
                        &raw mut info,
                        size_of::<MEMORY_BASIC_INFORMATION>(),
                    )
                },
                0
            );
            assert_eq!(info.State, state);
            if state == MEM_COMMIT {
                assert_eq!(info.Protect, PAGE_READWRITE);
            }
        }
    }
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
}

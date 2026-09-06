# Process and memory profile

The offline desktop profile requires successful process hardening before key
ownership, and successful locked allocation before retained keys enter it.
There is no unlocked fallback. Exhausted lock limits reject the operation.
This is protection against accidental dumps and paging, not privileged memory
inspection or code execution inside an unlocked process.

| Platform | Implemented protection | Evidence / limits |
| --- | --- | --- |
| Linux | `RLIMIT_CORE=0`; dedicated owners use `PR_SET_DUMPABLE=0`; anonymous page-aligned `mlock` allocations with inaccessible guards, `MADV_DONTDUMP`, and `MADV_WIPEONFORK` | Subprocess tests query process limits and lock failure; `/proc/self/smaps` verifies lock/dump flags; a fork test verifies child copies are zero. Linux 4.14+ is required for wipe-on-fork. IPC-only clients remain inspectable for `/proc/PID/exe` authentication. |
| macOS | `RLIMIT_CORE=0`; `mmap`, `mprotect` guards and `mlock` | Native tests require successful allocation and zeroing. Distribution signing/hardened runtime and OS task-port policy remain the debugger boundary; no claim of same-user debugger isolation in development builds. Forked copies are not covered by the parent's memory lock. |
| Windows | WER `NOHEAP`; `VirtualAlloc` guarded allocations, `VirtualLock`, and WER excluded-memory registration | Native subprocess test queries WER flags; allocation and guard-state tests run on Windows. Requires Windows 10 1703+. This does not override administrator full-dump policy or third-party dump tools. |
| Android/iOS core | Unix locked allocation, guards, and Android dump exclusion where available | Allocation errors propagate to the embedder. Physical mobile acceptance and host lifecycle/process hardening remain separate; no claim of native mobile production assurance. |

Root and index capabilities share one dedicated locked page during a lease.
Each live document DEK or unwrapped signing seed uses another page, released at
operation end. Fixed-size key unwrap decrypts directly into protected memory.
All key bytes are zeroized before unlocking, unregistering exclusions and
unmapping. Guard pages protect the allocation boundary, not every byte within
the usable page. Allocations are never shared with the general-purpose heap,
so dropping one cannot unlock another key's page.

The retained root's temporary bootstrap source, password inputs, decrypted
document/value buffers, Argon2 workspace, crypto key schedules/expanded signing
keys, GUI/native input methods, hardware API outputs, clipboard and OS/library
copies are not all locked. Existing zeroization narrows their lifetime but does
not erase earlier swap, snapshots, hibernation images or exported copies. The
profile requires normal OS access control and encrypted swap/hibernation where
those residual copies matter. Library embedders must also manage process
hardening, fork behavior, lifecycle and resource isolation themselves.

macOS and Windows CI serialize tests because their default lock budgets are
small. Product allocations retain only a few key pages; the 128 MiB password
workspace is deliberately not covered by that budget. A configured lock limit
too small for an operation is an explicit failure, not degraded protection.

Platform references:
[mlock](https://man7.org/linux/man-pages/man2/munlock.2.html),
[madvise](https://man7.org/linux/man-pages/man2/madvise.2.html),
[VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock),
[WER flags](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-wersetflags),
[WER memory exclusions](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-werregisterexcludedmemoryblock).

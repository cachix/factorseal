//! Restrictions are applied in a freshly exec'd, single-threaded helper before
//! it receives untrusted content. Failed enforcement is a startup error.

use std::io;
#[cfg(any(feature = "personal-sync-network", target_os = "macos"))]
use std::path::Path;

pub(super) fn parser() -> io::Result<()> {
    crate::security::disable_core_dumps()?;
    #[cfg(target_os = "linux")]
    return linux::parser();
    #[cfg(target_os = "macos")]
    return macos::install(None);
    #[cfg(windows)]
    return super::windows::verify(false);
    #[allow(unreachable_code)]
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "parser sandbox is unavailable",
    ))
}

#[cfg(feature = "personal-sync-network")]
pub(super) fn network(root: &Path) -> io::Result<()> {
    crate::security::disable_core_dumps()?;
    #[cfg(target_os = "linux")]
    return linux::network(root);
    #[cfg(target_os = "macos")]
    return macos::install(Some(root));
    #[cfg(windows)]
    {
        let _ = root;
        return super::windows::verify(true);
    }
    #[allow(unreachable_code)]
    {
        let _ = root;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "network sandbox is unavailable",
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter};
    use std::io;
    #[cfg(feature = "personal-sync-network")]
    use std::path::Path;

    fn filter(
        syscalls: impl IntoIterator<Item = i64>,
        default: SeccompAction,
        matched: SeccompAction,
    ) -> io::Result<()> {
        let filter: BpfProgram = SeccompFilter::new(
            syscalls
                .into_iter()
                .map(|number| (number, vec![]))
                .collect(),
            default,
            matched,
            std::env::consts::ARCH
                .try_into()
                .map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?
        .try_into()
        .map_err(io::Error::other)?;
        seccompiler::apply_filter(&filter).map_err(io::Error::other)
    }

    fn prepare() -> io::Result<()> {
        // SAFETY: scalar prctl arguments; this only restricts this helper.
        #[allow(unsafe_code)]
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // No descriptor other than stdin/out/err belongs to the helper. Close
        // unexpected inherited descriptors before installing a syscall filter.
        #[allow(unsafe_code)]
        if unsafe { libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    pub(super) fn parser() -> io::Result<()> {
        prepare()?;
        filter(
            [
                libc::SYS_read,
                libc::SYS_write,
                libc::SYS_readv,
                libc::SYS_writev,
                libc::SYS_close,
                libc::SYS_exit,
                libc::SYS_exit_group,
                libc::SYS_mmap,
                libc::SYS_mprotect,
                libc::SYS_munmap,
                libc::SYS_mremap,
                libc::SYS_brk,
                libc::SYS_madvise,
                libc::SYS_mlock,
                libc::SYS_munlock,
                libc::SYS_futex,
                libc::SYS_sched_yield,
                libc::SYS_clock_gettime,
                libc::SYS_clock_nanosleep,
                libc::SYS_nanosleep,
                libc::SYS_rt_sigaction,
                libc::SYS_rt_sigprocmask,
                libc::SYS_rt_sigreturn,
                libc::SYS_sigaltstack,
                libc::SYS_getrandom,
                libc::SYS_getpid,
                libc::SYS_gettid,
                libc::SYS_getuid,
                libc::SYS_geteuid,
                libc::SYS_getgid,
                libc::SYS_getegid,
                libc::SYS_fstat,
            ],
            SeccompAction::Errno(libc::EPERM.cast_unsigned()),
            SeccompAction::Allow,
        )
    }

    #[cfg(feature = "personal-sync-network")]
    pub(super) fn network(root: &Path) -> io::Result<()> {
        prepare()?;
        network_filesystem(root)?;
        network_syscalls()
    }

    #[cfg(feature = "personal-sync-network")]
    fn network_filesystem(root: &Path) -> io::Result<()> {
        use landlock::{
            ABI, Access, AccessFs, CompatLevel, Compatible, PathBeneath, PathFd, Ruleset,
            RulesetAttr, RulesetCreatedAttr, RulesetStatus,
        };
        let abi = ABI::V3;
        let mut rules = Ruleset::default()
            .set_compatibility(CompatLevel::HardRequirement)
            .handle_access(AccessFs::from_all(abi))
            .map_err(io::Error::other)?
            .create()
            .map_err(io::Error::other)?;
        rules = rules
            .add_rule(PathBeneath::new(
                PathFd::new(root).map_err(io::Error::other)?,
                AccessFs::from_all(abi),
            ))
            .map_err(io::Error::other)?;
        for path in [
            "/usr",
            "/lib",
            "/lib64",
            "/nix/store",
            "/etc/ssl",
            "/etc/pki",
            "/etc/resolv.conf",
            "/etc/hosts",
            "/etc/nsswitch.conf",
            "/run/systemd/resolve",
            "/dev/urandom",
            "/dev/null",
        ] {
            if Path::new(path).exists() {
                let access = if Path::new(path).is_dir() {
                    AccessFs::from_read(abi)
                } else {
                    AccessFs::ReadFile.into()
                };
                rules = rules
                    .add_rule(PathBeneath::new(
                        PathFd::new(path).map_err(io::Error::other)?,
                        access,
                    ))
                    .map_err(io::Error::other)?;
            }
        }
        let status = rules.restrict_self().map_err(io::Error::other)?;
        if status.ruleset != RulesetStatus::FullyEnforced {
            return Err(io::Error::other(
                "network filesystem sandbox is not fully enforced",
            ));
        }
        Ok(())
    }

    #[cfg(feature = "personal-sync-network")]
    fn network_syscalls() -> io::Result<()> {
        use seccompiler::{SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompRule};
        // The network helper needs normal threads and sockets, but has no
        // reason to inspect another process, execute code, or alter the kernel.
        let denied = [
            libc::SYS_ptrace,
            libc::SYS_process_vm_readv,
            libc::SYS_process_vm_writev,
            libc::SYS_pidfd_getfd,
            libc::SYS_perf_event_open,
            libc::SYS_bpf,
            libc::SYS_execve,
            libc::SYS_execveat,
            libc::SYS_mount,
            libc::SYS_umount2,
            libc::SYS_pivot_root,
            libc::SYS_chroot,
            libc::SYS_setns,
            libc::SYS_unshare,
            libc::SYS_open_by_handle_at,
            libc::SYS_name_to_handle_at,
            libc::SYS_keyctl,
            libc::SYS_add_key,
            libc::SYS_request_key,
            libc::SYS_kill,
            libc::SYS_tkill,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ];
        let condition = |index, operation, value| {
            SeccompRule::new(vec![
                SeccompCondition::new(index, SeccompCmpArgLen::Qword, operation, value)
                    .map_err(io::Error::other)?,
            ])
            .map_err(io::Error::other)
        };
        let mut rules: std::collections::BTreeMap<_, _> =
            denied.into_iter().map(|number| (number, vec![])).collect();
        #[cfg(target_arch = "x86_64")]
        {
            rules.insert(libc::SYS_fork, vec![]);
            rules.insert(libc::SYS_vfork, vec![]);
        }
        // Threads are necessary for the runtime, but creating a new process is
        // not. ENOSYS makes libc use clone, whose flags we can inspect.
        filter(
            [libc::SYS_clone3],
            SeccompAction::Allow,
            SeccompAction::Errno(libc::ENOSYS.cast_unsigned()),
        )?;
        rules.insert(
            libc::SYS_clone,
            vec![condition(
                0,
                SeccompCmpOp::MaskedEq(libc::CLONE_THREAD as u64),
                0,
            )?],
        );
        rules.insert(
            libc::SYS_tgkill,
            vec![condition(
                0,
                SeccompCmpOp::Ne,
                u64::from(std::process::id()),
            )?],
        );
        // An inherited control socket is sufficient. New Unix sockets could
        // reach the user's local secret service or other privileged brokers.
        rules.insert(
            libc::SYS_socket,
            vec![
                SeccompRule::new(
                    [libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK]
                        .into_iter()
                        .map(|family| {
                            SeccompCondition::new(
                                0,
                                SeccompCmpArgLen::Qword,
                                SeccompCmpOp::Ne,
                                u64::from(family.cast_unsigned()),
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?,
            ],
        );
        // socketpair creates only private endpoints; Tokio uses one for its
        // signal driver. It cannot connect to any pre-existing local service.
        let program: BpfProgram = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM.cast_unsigned()),
            std::env::consts::ARCH
                .try_into()
                .map_err(io::Error::other)?,
        )
        .map_err(io::Error::other)?
        .try_into()
        .map_err(io::Error::other)?;
        seccompiler::apply_filter(&program).map_err(io::Error::other)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use super::{Path, io};
    use std::ffi::{CString, c_char};
    use std::fmt::Write as _;

    pub(super) fn install(root: Option<&Path>) -> io::Result<()> {
        close_inherited_descriptors()?;
        let mut profile = String::from(
            "(version 1)\n(deny default)\n(allow sysctl-read)\n(allow process-info* (target self))\n(allow signal (target self))\n(allow file-read* (subpath \"/System/Library\") (subpath \"/usr/lib\"))\n",
        );
        if let Some(root) = root {
            let root = root
                .to_str()
                .ok_or_else(|| io::Error::other("sandbox path is not UTF-8"))?;
            let escaped = root.replace('\\', "\\\\").replace('"', "\\\"");
            writeln!(
                profile,
                "(allow file-read* file-write* (subpath \"{escaped}\"))"
            )
            .expect("format into String");
            // SystemConfiguration formats network-interface display names
            // using ICU. Without its public data CFNumberFormatter creation
            // fails inside Apple's unchecked display-name implementation.
            profile.push_str("(allow file-read* (subpath \"/usr/share/icu\"))\n");
            // netwatch subscribes to interface/route changes with AF_ROUTE.
            // This permits that socket domain, not arbitrary system sockets.
            writeln!(
                profile,
                "(allow system-socket (socket-domain {}))",
                libc::AF_ROUTE
            )
            .expect("format into String");
            profile.push_str("(allow network-outbound (remote ip \"*:*\"))\n(allow network-inbound network-bind (local ip \"*:*\"))\n(allow file-read* (subpath \"/private/etc/ssl\") (literal \"/private/etc/resolv.conf\") (literal \"/private/etc/hosts\") (subpath \"/private/var/run/resolv.conf\"))\n(allow mach-lookup (global-name \"com.apple.trustd\") (global-name \"com.apple.networkd\") (global-name \"com.apple.SystemConfiguration.configd\"))\n");
        }
        let profile = CString::new(profile).map_err(io::Error::other)?;
        let mut error = std::ptr::null_mut();
        // SAFETY: profile is NUL-terminated and live; the OS owns any returned
        // error buffer, freed exactly once below. No error contents are logged.
        #[allow(unsafe_code)]
        let status = unsafe { sandbox_init(profile.as_ptr(), 0, &raw mut error) };
        if !error.is_null() {
            #[allow(unsafe_code)]
            unsafe {
                sandbox_free_error(error);
            }
        }
        if status != 0 {
            return Err(io::Error::other("cannot enforce helper sandbox"));
        }
        Ok(())
    }

    fn close_inherited_descriptors() -> io::Result<()> {
        let pid = std::process::id().try_into().map_err(io::Error::other)?;
        // SAFETY: a null buffer and zero length ask libproc for a size estimate.
        #[allow(unsafe_code)]
        let required =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if required <= 0 || required > 1024 * 1024 {
            return Err(io::Error::other(
                "cannot enumerate inherited helper descriptors",
            ));
        }
        let count = usize::try_from(required).map_err(io::Error::other)?
            / std::mem::size_of::<libc::proc_fdinfo>()
            + 32;
        let mut entries = vec![
            libc::proc_fdinfo {
                proc_fd: -1,
                proc_fdtype: 0
            };
            count
        ];
        let capacity =
            i32::try_from(std::mem::size_of_val(entries.as_slice())).map_err(io::Error::other)?;
        // SAFETY: the typed buffer is initialized, aligned, and writable for
        // exactly capacity bytes. No untrusted helper input has been read yet.
        #[allow(unsafe_code)]
        let written = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDLISTFDS,
                0,
                entries.as_mut_ptr().cast(),
                capacity,
            )
        };
        if written <= 0 || written >= capacity || written % libc::PROC_PIDLISTFD_SIZE != 0 {
            return Err(io::Error::other(
                "incomplete inherited descriptor enumeration",
            ));
        }
        for entry in entries
            .iter()
            .take(usize::try_from(written / libc::PROC_PIDLISTFD_SIZE).map_err(io::Error::other)?)
        {
            if entry.proc_fd >= 3 {
                // SAFETY: this single-threaded helper exclusively owns the
                // enumerated inherited descriptors; only stdin/out/err survive.
                #[allow(unsafe_code)]
                if unsafe { libc::close(entry.proc_fd) } != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        Ok(())
    }

    #[link(name = "sandbox")]
    #[allow(unsafe_code)]
    unsafe extern "C" {
        fn sandbox_init(profile: *const c_char, flags: u64, error: *mut *mut c_char) -> i32;
        fn sandbox_free_error(error: *mut c_char);
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        process::{Command, Stdio},
    };

    #[test]
    fn parser_cannot_open_files_sockets_or_processes() {
        probe("parser");
    }

    #[cfg(feature = "personal-sync-network")]
    #[test]
    fn network_can_use_its_spool_and_threads_but_cannot_reach_local_secrets() {
        probe("network");
    }

    #[cfg(feature = "personal-sync-network")]
    #[test]
    fn network_runtime_starts_under_confinement() {
        probe("runtime");
    }

    fn probe(mode: &str) {
        let fixture = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(fixture.path()).unwrap();
        std::fs::create_dir(root.join("spool")).unwrap();
        std::fs::write(root.join("vault-secret"), b"test secret").unwrap();
        let control = root.join("control.sock");
        let listener = std::os::unix::net::UnixListener::bind(&control).unwrap();
        drop(std::os::unix::net::UnixStream::connect(&control).unwrap());
        drop(listener.accept().unwrap());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "isolation::sandbox::tests::sandbox_probe",
                "--nocapture",
            ])
            .env("FACTORSEAL_SANDBOX_TEST", mode)
            .env("FACTORSEAL_SANDBOX_FIXTURE", &root)
            .env("FACTORSEAL_SANDBOX_PARENT", std::process::id().to_string())
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let status = child.wait().unwrap();
        assert!(status.success(), "sandbox probe failed: {status}");
    }

    #[test]
    fn sandbox_probe() {
        let Ok(mode) = std::env::var("FACTORSEAL_SANDBOX_TEST") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("FACTORSEAL_SANDBOX_FIXTURE").unwrap());
        let secret = root.join("vault-secret");
        let spool = root.join("spool");
        let parent: libc::pid_t = std::env::var("FACTORSEAL_SANDBOX_PARENT")
            .unwrap()
            .parse()
            .unwrap();
        match mode.as_str() {
            #[cfg(feature = "personal-sync-network")]
            "runtime" => {
                network(&spool).unwrap();
                let manager = crate::desktop_worker::sync::network::Manager::open(
                    &spool,
                    std::sync::Arc::new(|_| Err("vault is sealed".into())),
                )
                .unwrap();
                assert_ne!(manager.view().endpoint, [0; 32]);
                drop(manager);
                return;
            }
            "parser" => {
                parser().unwrap();
                assert!(std::fs::write(spool.join("packet"), b"ciphertext").is_err());
                assert!(std::net::UdpSocket::bind("127.0.0.1:0").is_err());
                #[cfg(target_os = "linux")]
                {
                    assert!(std::os::unix::net::UnixStream::pair().is_err());
                    assert!(std::thread::Builder::new().spawn(|| {}).is_err());
                }
            }
            #[cfg(feature = "personal-sync-network")]
            "network" => {
                use std::time::Duration;
                network(&spool).unwrap();
                let path = spool.join("packet");
                std::fs::write(&path, b"ciphertext").unwrap();
                assert_eq!(std::fs::read(&path).unwrap(), b"ciphertext");
                std::thread::Builder::new()
                    .spawn(|| {
                        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
                        socket
                            .set_read_timeout(Some(Duration::from_secs(1)))
                            .unwrap();
                        socket
                            .send_to(b"network", socket.local_addr().unwrap())
                            .unwrap();
                        let mut bytes = [0; 7];
                        assert_eq!(socket.recv(&mut bytes).unwrap(), 7);
                        assert_eq!(&bytes, b"network");
                    })
                    .unwrap()
                    .join()
                    .unwrap();
            }
            _ => panic!("unknown probe mode"),
        }
        assert!(std::fs::read(secret).is_err());
        assert_eq!(
            std::os::unix::net::UnixStream::connect(root.join("control.sock"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert!(
            Command::new("/bin/sh")
                .arg("-c")
                .arg("exit 0")
                .status()
                .is_err()
        );
        // Signal zero tests permission without delivering a signal.
        #[allow(unsafe_code)]
        let signal = unsafe { libc::kill(parent, 0) };
        assert_eq!(signal, -1);
    }
}

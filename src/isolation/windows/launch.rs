use std::{io, mem::size_of, os::windows::io::OwnedHandle, path::Path};
use windows::Win32::{
    Security::{SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES},
    System::{
        JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOB_OBJECT_UILIMIT_DESKTOP,
            JOB_OBJECT_UILIMIT_DISPLAYSETTINGS, JOB_OBJECT_UILIMIT_EXITWINDOWS,
            JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
            JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
            JOB_OBJECT_UILIMIT_WRITECLIPBOARD, JOBOBJECT_BASIC_LIMIT_INFORMATION,
            JOBOBJECT_BASIC_UI_RESTRICTIONS, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JobObjectBasicUIRestrictions, JobObjectExtendedLimitInformation,
            SetInformationJobObject, TerminateJobObject,
        },
        Threading::{
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, DETACHED_PROCESS,
            DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
            InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
            PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
            PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, ResumeThread,
            STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW, TerminateProcess,
            UpdateProcThreadAttribute, WaitForSingleObject,
        },
        WindowsProgramming::{
            PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
            PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
        },
    },
};
use windows::core::{HSTRING, PCWSTR};

use super::{Channel, access, channel, error, owned, raw};
// Win32k, extension-point, and dynamic-code prohibitions, set at creation.
const MITIGATIONS: u64 = (1_u64 << 28) | (1_u64 << 32) | (1_u64 << 36);
pub(in crate::isolation) struct Owner {
    process: OwnedHandle,
    job: OwnedHandle,
    _identity: access::Identity,
}
impl Owner {
    #[cfg(feature = "personal-sync-network")]
    pub(in crate::isolation) fn exited_error(&self, message: String) -> String {
        use windows::Win32::{Foundation::WAIT_OBJECT_0, System::Threading::GetExitCodeProcess};
        // A failed private channel may precede process teardown briefly. Keep
        // the native exit code before stop() replaces it with our kill status.
        let mut status = 0;
        if unsafe { WaitForSingleObject(raw(&self.process), 250) } == WAIT_OBJECT_0
            && unsafe { GetExitCodeProcess(raw(&self.process), &raw mut status) }.is_ok()
        {
            format!("{message} (network helper exit {status:#010x})")
        } else {
            message
        }
    }

    pub(in crate::isolation) fn stop(&mut self) {
        // SAFETY: both handles remain owned until after termination and wait.
        unsafe {
            let _ = TerminateJobObject(raw(&self.job), 1);
            let _ = TerminateProcess(raw(&self.process), 1);
            let _ = WaitForSingleObject(raw(&self.process), 5000);
        }
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(in crate::isolation) fn spawn(
    path: &Path,
    root: Option<&Path>,
) -> io::Result<(Owner, Channel)> {
    spawn_program(path, root, &[])
}

fn spawn_program(
    path: &Path,
    root: Option<&Path>,
    arguments: &[&str],
) -> io::Result<(Owner, Channel)> {
    let identity = access::Identity::new(path, root)
        .map_err(|error| super::at("prepare AppContainer identity and files", &error))?;
    let (parent, input) =
        channel::pair().map_err(|error| super::at("prepare private helper pipe", &error))?;
    let handles = [raw(&input)];
    let mut capabilities: Vec<_> = identity
        .capabilities
        .iter()
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid.raw(),
            Attributes: 4, /* SE_GROUP_ENABLED */
        })
        .collect();
    let security = SECURITY_CAPABILITIES {
        AppContainerSid: identity.package.raw(),
        Capabilities: capabilities.as_mut_ptr(),
        CapabilityCount: u32::try_from(capabilities.len()).map_err(io::Error::other)?,
        Reserved: 0,
    };
    let no_ambient_packages = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    let no_children = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
    let job = create_job(root.is_some())
        .map_err(|error| super::at("create restricted helper job", &error))?;
    let jobs = [raw(&job)];
    // Creation-time Win32k, extension-point, and dynamic-code prohibitions.
    // These documented mitigation bits cannot be relaxed by the child.
    let mitigations = MITIGATIONS;
    let mut attributes = Attributes::new(6)?;
    attributes.add(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &security)?;
    attributes.add(
        PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        &no_ambient_packages,
    )?;
    attributes.add(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &no_children)?;
    attributes.add(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &mitigations)?;
    attributes.add(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &handles)?;
    attributes.add(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: u32::try_from(size_of::<STARTUPINFOEXW>()).expect("startup structure"),
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: raw(&input),
            hStdOutput: raw(&input),
            // No separate stderr authority is inherited. Panic messages make
            // the private framing invalid and therefore fail the operation.
            hStdError: raw(&input),
            ..Default::default()
        },
        lpAttributeList: attributes.raw(),
    };
    let executable = HSTRING::from(identity.code.path().join("helper.exe").as_path());
    let mut command: Vec<u16> = std::iter::once(u16::from(b'"'))
        .chain(executable.iter().copied())
        .chain(std::iter::once(u16::from(b'"')))
        .collect();
    for argument in arguments {
        // All arguments are internal test-harness literals, never caller data.
        if !argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:".contains(&byte))
        {
            return Err(io::Error::other("invalid helper argument"));
        }
        command.push(u16::from(b' '));
        command.extend(argument.encode_utf16());
    }
    command.push(0);
    let environment = runtime_environment()?;
    let system_directory = system_directory()?;
    let mut information = PROCESS_INFORMATION::default();
    // SAFETY: every attribute points into live owned storage until creation
    // completes. The child starts suspended, already inside its LPAC token.
    unsafe {
        CreateProcessW(
            &executable,
            Some(windows::core::PWSTR(command.as_mut_ptr())),
            None,
            None,
            true,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_SUSPENDED
                // Helpers use inherited pipes and need no console host.
                // CREATE_NO_WINDOW still requests a windowless console.
                | DETACHED_PROCESS
                | CREATE_UNICODE_ENVIRONMENT,
            Some(environment.as_ptr().cast()),
            PCWSTR(system_directory.as_ptr()),
            &raw const startup.StartupInfo,
            &raw mut information,
        )
    }
    .map_err(error)
    .map_err(|error| super::at("create AppContainer process", &error))?;
    let owner = Owner {
        process: owned(information.hProcess)?,
        job,
        _identity: identity,
    };
    let thread = owned(information.hThread)?;
    // The job is attached atomically by CreateProcessW, so even a parent crash
    // between creation and resume cannot leave an unowned suspended helper.
    if unsafe { ResumeThread(raw(&thread)) } == u32::MAX {
        return Err(io::Error::last_os_error());
    }
    Ok((owner, parent))
}

fn system_directory() -> io::Result<Vec<u16>> {
    let mut system_directory = vec![0_u16; 32768];
    let length = unsafe {
        windows::Win32::System::SystemInformation::GetSystemDirectoryW(Some(&mut system_directory))
    };
    if length == 0 || length as usize >= system_directory.len() {
        return Err(io::Error::other(
            "cannot locate the Windows system directory",
        ));
    }
    Ok(system_directory)
}

fn runtime_environment() -> io::Result<Vec<u16>> {
    // Windows runtime components, including Winsock, need SystemRoot even in
    // an otherwise empty environment. Obtain it from the OS, never from the
    // parent's potentially secret-bearing or caller-controlled environment.
    let mut root = vec![0_u16; 32768];
    let length = unsafe {
        windows::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(Some(&mut root))
    } as usize;
    if length == 0 || length >= root.len() {
        return Err(io::Error::other("cannot locate the Windows runtime root"));
    }
    // AppContainer creation derives its redirected directories from
    // LOCALAPPDATA. The Known Folder API supplies the current user's path
    // without copying any parent environment entries.
    let app_data = unsafe {
        windows::Win32::UI::Shell::SHGetKnownFolderPath(
            &windows::Win32::UI::Shell::FOLDERID_LocalAppData,
            windows::Win32::UI::Shell::KF_FLAG_DEFAULT,
            None,
        )
    }
    .map_err(error)?;
    let mut environment: Vec<_> = "LOCALAPPDATA=".encode_utf16().collect();
    // SAFETY: SHGetKnownFolderPath returns a CoTaskMem-allocated terminated
    // string. Copy it before freeing that allocation exactly once.
    unsafe {
        environment.extend_from_slice(app_data.as_wide());
        windows::Win32::System::Com::CoTaskMemFree(Some(app_data.0.cast()));
    }
    environment.push(0);
    environment.extend("SystemRoot=".encode_utf16());
    environment.extend_from_slice(&root[..length]);
    environment.extend_from_slice(&[0, 0]);
    Ok(environment)
}

fn create_job(network: bool) -> io::Result<OwnedHandle> {
    // SAFETY: unnamed job, no inheritable handle or external object name.
    let job = owned(unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(error)?)?;
    let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
            LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                | JOB_OBJECT_LIMIT_PROCESS_MEMORY,
            ActiveProcessLimit: 1,
            ..Default::default()
        },
        ProcessMemoryLimit: if network {
            512 * 1024 * 1024
        } else {
            64 * 1024 * 1024
        },
        ..Default::default()
    };
    let ui = JOBOBJECT_BASIC_UI_RESTRICTIONS {
        UIRestrictionsClass: JOB_OBJECT_UILIMIT_HANDLES
            | JOB_OBJECT_UILIMIT_READCLIPBOARD
            | JOB_OBJECT_UILIMIT_WRITECLIPBOARD
            | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
            | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
            | JOB_OBJECT_UILIMIT_GLOBALATOMS
            | JOB_OBJECT_UILIMIT_DESKTOP
            | JOB_OBJECT_UILIMIT_EXITWINDOWS,
    };
    // SAFETY: documented structures and exact buffer sizes; job is owned.
    unsafe {
        SetInformationJobObject(
            raw(&job),
            JobObjectExtendedLimitInformation,
            (&raw const limits).cast(),
            u32::try_from(size_of_val(&limits)).expect("job limits"),
        )?;
        SetInformationJobObject(
            raw(&job),
            JobObjectBasicUIRestrictions,
            (&raw const ui).cast(),
            u32::try_from(size_of_val(&ui)).expect("UI limits"),
        )
    }
    .map_err(error)?;
    Ok(job)
}

struct Attributes {
    storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    fn raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.storage.as_ptr().cast_mut().cast())
    }
    fn new(count: u32) -> io::Result<Self> {
        let mut bytes = 0;
        // SAFETY: documented size query, followed by aligned initialized storage.
        let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &raw mut bytes) };
        if bytes == 0 || bytes > 65536 {
            return Err(io::Error::other("invalid process attribute size"));
        }
        let mut value = Self {
            storage: vec![0; bytes.div_ceil(size_of::<usize>())],
            initialized: false,
        };
        unsafe {
            InitializeProcThreadAttributeList(Some(value.raw()), count, None, &raw mut bytes)
        }
        .map_err(error)?;
        value.initialized = true;
        Ok(value)
    }
    fn add<T>(&mut self, attribute: u32, value: &T) -> io::Result<()> {
        // SAFETY: caller keeps each pointed-to value live through CreateProcessW.
        unsafe {
            UpdateProcThreadAttribute(
                self.raw(),
                0,
                attribute as usize,
                Some(std::ptr::from_ref(value).cast()),
                size_of::<T>(),
                None,
                None,
            )
        }
        .map_err(error)
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.raw());
            }
        }
    }
}

#[cfg(all(test, feature = "personal-sync-network"))]
mod tests {
    use super::*;
    use crate::isolation::codec;
    use crate::isolation::windows::{current_app_sid, verify};
    use serde::{Deserialize, Serialize};
    use std::{io::Read, path::PathBuf};
    use windows::Win32::{
        Foundation::WAIT_OBJECT_0,
        Networking::WinSock::{WSACleanup, WSADATA, WSAStartup},
        System::Threading::{GetExitCodeProcess, OpenProcess, PROCESS_VM_READ},
    };

    #[derive(Serialize, Deserialize)]
    struct Probe {
        network: bool,
        root: PathBuf,
        parent: u32,
        listener: std::net::SocketAddr,
    }

    #[test]
    fn parser_appcontainer_cannot_read_vault_files_inspect_parent_or_spawn() {
        probe(false);
    }
    #[test]
    fn network_appcontainer_can_reopen_its_private_files_but_not_vault_files() {
        probe(true);
    }

    fn probe(network: bool) {
        let fixture = tempfile::tempdir().unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        // A live, reachable endpoint makes the parser denial meaningful;
        // connecting to an unused port would also fail without confinement.
        drop(std::net::TcpStream::connect(address).unwrap());
        drop(listener.accept().unwrap());
        let root = fixture.path().join("spool");
        crate::security::windows::create_owner_only_directory(&root).unwrap();
        std::fs::write(fixture.path().join("vault-secret"), b"synthetic secret").unwrap();
        let (owner, mut channel) = spawn_program(
            &std::env::current_exe().unwrap(),
            network.then_some(root.as_path()),
            &[
                "--exact",
                "isolation::windows::launch::tests::sandbox_probe",
                "--nocapture",
            ],
        )
        .unwrap();
        codec::send(
            &mut channel,
            &Probe {
                network,
                root,
                parent: std::process::id(),
                listener: address,
            },
            16384,
        )
        .unwrap();
        assert_eq!(
            unsafe { WaitForSingleObject(raw(&owner.process), 15000) },
            WAIT_OBJECT_0,
            "sandbox probe did not exit"
        );
        let mut status = 0;
        unsafe { GetExitCodeProcess(raw(&owner.process), &raw mut status) }.unwrap();
        let mut output = Vec::new();
        channel.take(16384).read_to_end(&mut output).unwrap();
        assert_eq!(status, 0, "{}", String::from_utf8_lossy(&output));
    }

    #[test]
    fn sandbox_probe() {
        if current_app_sid().unwrap().is_none() {
            return;
        }
        let input: Probe =
            codec::decode(&codec::read(&mut io::stdin().lock(), 16384).unwrap(), 16384).unwrap();
        verify(input.network).unwrap();
        // Exercise protected protocol storage beyond Windows' default lock
        // quota under the actual restricted token, for both helper roles.
        let buffer = crate::security::LockedBytes::zeroed(2 * 1024 * 1024).unwrap();
        assert_eq!(buffer.len(), 2 * 1024 * 1024);
        drop(buffer);
        assert!(std::fs::read(input.root.parent().unwrap().join("vault-secret")).is_err());
        assert!(
            std::fs::write(
                input.root.parent().unwrap().join("leak"),
                b"no write authority"
            )
            .is_err()
        );
        assert!(unsafe { OpenProcess(PROCESS_VM_READ, false, input.parent) }.is_err());
        let mut system = vec![0_u16; 32768];
        let length = unsafe {
            windows::Win32::System::SystemInformation::GetSystemDirectoryW(Some(&mut system))
        };
        let executable =
            PathBuf::from(String::from_utf16(&system[..length as usize]).unwrap()).join("cmd.exe");
        assert!(
            std::process::Command::new(executable)
                .args(["/c", "exit", "0"])
                .status()
                .is_err()
        );
        let file = input.root.join("transport.key");
        if input.network {
            crate::security::write_private_file(&file, b"transport material").unwrap();
            assert_eq!(
                &**crate::security::read_private_file(&file, 64).unwrap(),
                b"transport material"
            );
            std::thread::spawn(|| std::net::UdpSocket::bind("0.0.0.0:0").unwrap())
                .join()
                .unwrap();
        } else {
            assert!(std::fs::write(file, b"must not persist").is_err());
            // With no registry capability Winsock can be denied before socket
            // creation. std::net panics on that initialization error, so probe
            // it explicitly and only try the live endpoint if it succeeds.
            let mut data = WSADATA::default();
            let initialized = unsafe { WSAStartup(0x0202, &raw mut data) };
            if initialized == 0 {
                let result = std::net::TcpStream::connect_timeout(
                    &input.listener,
                    std::time::Duration::from_secs(1),
                );
                unsafe { WSACleanup() };
                assert!(result.is_err(), "parser connected to a live endpoint");
            } else {
                assert_eq!(
                    initialized, 10107,
                    "unexpected Winsock initialization failure"
                );
            }
        }
    }
}

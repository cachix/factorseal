use super::registration::Registration;
use super::{Local, NETWORK_CAPABILITIES, Sid, error, string};
use nt_token::OwnedToken;
use std::{
    fs::OpenOptions,
    io,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
};
use windows::Win32::{
    Foundation::{ERROR_SUCCESS, HANDLE},
    Security::{
        Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_FILE_OBJECT, SetSecurityInfo,
        },
        DACL_SECURITY_INFORMATION, FreeSid, GetSecurityDescriptorDacl,
        Isolation::DeriveAppContainerSidFromAppContainerName,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    },
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, CreateDirectoryW, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        GetFileInformationByHandle, READ_CONTROL, WRITE_DAC,
    },
};
use windows::core::HSTRING;
pub(in crate::isolation::windows) struct Identity {
    pub(in crate::isolation::windows) package: Sid,
    pub(in crate::isolation::windows) capabilities: Vec<Sid>,
    pub(in crate::isolation::windows) code: CodeDirectory,
    _registration: Registration,
}
impl Identity {
    pub(in crate::isolation::windows) fn new(
        executable: &Path,
        root: Option<&Path>,
    ) -> io::Result<Self> {
        let user = OwnedToken::from_current_process(TOKEN_QUERY)
            .map_err(error)?
            .user()
            .map_err(error)?
            .to_string()
            .map_err(error)?;
        // Every launch owns its registration, including concurrent parser
        // requests. No writable profile or AppData directory is created.
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|error| io::Error::other(error.to_string()))?;
        let name = HSTRING::from(format!("dev.factorseal.helper.{}", hex::encode(nonce)));
        let allocated =
            unsafe { DeriveAppContainerSidFromAppContainerName(&name) }.map_err(error)?;
        let package = Sid::copy(allocated);
        unsafe {
            FreeSid(allocated);
        }
        let package = package?;
        let registration = Registration::new(&package, &name)?;
        let capabilities = if root.is_some() {
            NETWORK_CAPABILITIES
                .iter()
                .map(|name| Sid::capability(name))
                .collect::<io::Result<_>>()?
        } else {
            Vec::new()
        };
        // Installed MSIX/Program Files binaries may have immutable ACLs. Make
        // a private executable copy and grant RX only there, never on the
        // installation directory or on a parent of the vault.
        let code = CodeDirectory::new(&user, &package)?;
        std::fs::copy(executable, code.path().join("helper.exe"))?;
        if let Some(root) = root {
            protect_tree(root, &user, &package, 0, &mut 0)?;
        }
        Ok(Self {
            package,
            capabilities,
            code,
            _registration: registration,
        })
    }
}

pub(in crate::isolation::windows) struct CodeDirectory(std::path::PathBuf);
impl CodeDirectory {
    fn new(user: &str, package: &Sid) -> io::Result<Self> {
        let mut nonce = [0; 24];
        getrandom::fill(&mut nonce).map_err(|error| io::Error::other(error.to_string()))?;
        let path = std::env::temp_dir().join(format!("factorseal-helper-{}", hex::encode(nonce)));
        let sddl = HSTRING::from(format!(
            "O:{user}D:P(A;OICI;FA;;;{user})(A;OICI;GRGX;;;{})",
            package.string()?
        ));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &sddl,
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(error)?;
        let _descriptor = Local(descriptor.0);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).expect("attributes"),
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: false.into(),
        };
        // Explicit user ownership also works when the parent has an elevated
        // token whose default owner would otherwise be the Administrators group.
        unsafe { CreateDirectoryW(&HSTRING::from(path.as_path()), Some(&raw const attributes)) }
            .map_err(error)?;
        Ok(Self(path))
    }
    pub(in crate::isolation::windows) fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for CodeDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn protect_tree(
    path: &Path,
    user: &str,
    package: &Sid,
    depth: usize,
    count: &mut usize,
) -> io::Result<()> {
    *count += 1;
    if depth > 16 || *count > 100_000 {
        return Err(io::Error::other("network spool tree exceeds bounds"));
    }
    let directory = protect(path, user, package)?;
    if directory {
        for entry in std::fs::read_dir(path)? {
            protect_tree(&entry?.path(), user, package, depth + 1, count)?;
        }
    }
    Ok(())
}

/// Apply grants through the same validated handle: no reparse points or file
/// hardlinks can turn a spool grant into access to another vault artifact.
fn protect(path: &Path, user: &str, package: &Sid) -> io::Result<bool> {
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL.0 | WRITE_DAC.0 | FILE_READ_ATTRIBUTES.0)
        .share_mode(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_BACKUP_SEMANTICS.0)
        .open(path)?;
    let handle = HANDLE(file.as_raw_handle());
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(handle, &raw mut info) }.map_err(error)?;
    let directory = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(io::Error::other(
            "sandbox paths cannot contain reparse points or hardlinks",
        ));
    }
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            None,
            None,
            Some(&raw mut descriptor),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(result.0.cast_signed()));
    }
    let _descriptor = Local(descriptor.0);
    if owner.0.is_null() || string(owner)? != user {
        return Err(io::Error::other(
            "sandbox path is not owned by the current user",
        ));
    }
    let rights = "0x001301bf";
    let inherit = if directory { "OICI" } else { "" };
    let sddl = HSTRING::from(format!(
        "D:P(A;{inherit};FA;;;{user})(A;{inherit};{rights};;;{})",
        package.string()?
    ));
    let mut updated = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &raw mut updated,
            None,
        )
    }
    .map_err(error)?;
    let _updated = Local(updated.0);
    let (mut present, mut defaulted) = (
        windows::core::BOOL::default(),
        windows::core::BOOL::default(),
    );
    let mut dacl = std::ptr::null_mut();
    unsafe {
        GetSecurityDescriptorDacl(updated, &raw mut present, &raw mut dacl, &raw mut defaulted)
    }
    .map_err(error)?;
    if !present.as_bool() || dacl.is_null() {
        return Err(io::Error::other("invalid sandbox DACL"));
    }
    let status = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.0.cast_signed()));
    }
    Ok(directory)
}

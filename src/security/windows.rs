//! Owner-only permissions for the vault root on Windows.
//!
//! `std::fs` cannot express a discretionary access control list, so the root
//! is created through `CreateDirectoryW` with a protected security descriptor
//! that grants full control to the current user only and inherits nothing
//! from its parent. Validation reads the DACL back and rejects any grant to
//! another trustee, mirroring the mode-0700 check on Unix.
//!
//! The unsafe operations in this module are Win32 calls whose out-pointers
//! reference live locals, plus reads of the buffers those calls allocate,
//! which [`LocalMemory`] guards free.

#![allow(unsafe_code)]

use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::path::Path;
use std::ptr;

use nt_token::OwnedToken;
#[cfg(any(feature = "transfer", feature = "personal-sync"))]
use std::{
    fs::File,
    os::windows::io::{AsRawHandle, FromRawHandle},
};
use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree, WIN32_ERROR};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GetAce, IsValidAcl,
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
};
#[cfg(feature = "key-protection")]
use windows::Win32::{
    Security::{
        Authorization::GetNamedSecurityInfoW, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
        SE_DACL_PROTECTED,
    },
    Storage::FileSystem::CreateDirectoryW,
};
use windows::core::{HSTRING, PWSTR};

/// Frees a `LocalAlloc` buffer returned by a Win32 call when dropped.
struct LocalMemory(*mut c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Win32 call that documents
            // `LocalFree` as its release function, and it is freed once.
            unsafe { LocalFree(Some(HLOCAL(self.0))) };
        }
    }
}

/// String SID of the user the vault process runs as.
fn current_user_sid() -> io::Result<String> {
    let token = OwnedToken::from_current_process(TOKEN_QUERY)
        .map_err(|error| io::Error::other(format!("could not open the process token: {error}")))?;
    let user = token
        .user()
        .map_err(|error| io::Error::other(format!("could not read the process user: {error}")))?;
    user.to_string().map_err(|error| {
        io::Error::other(format!("could not format the process user SID: {error}"))
    })
}

/// Create the final private ACL before writing any secret bytes.
#[cfg(any(feature = "transfer", feature = "personal-sync"))]
pub(crate) fn create_private_file(path: &Path) -> io::Result<File> {
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
    use windows::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
    };
    let sid = current_user_sid()?;
    let sddl = HSTRING::from(format!("O:{sid}D:P(A;;FA;;;{sid})"));
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: live output pointer; LocalMemory releases the allocated descriptor.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|e| win32_io_error(&e))?;
    let _descriptor = LocalMemory(descriptor.0);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .expect("security attributes fit in u32"),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    // SAFETY: path and descriptor remain alive for the call.
    let handle = unsafe {
        CreateFileW(
            &HSTRING::from(path),
            GENERIC_READ.0 | GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            Some(&raw const attributes),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .map_err(|e| win32_io_error(&e))?;
    // SAFETY: transfer the newly allocated handle into File exactly once.
    Ok(unsafe { File::from_raw_handle(handle.0) })
}

/// Validate the same handle used to read the factor, including its owner.
#[cfg(any(feature = "transfer", feature = "personal-sync"))]
pub(crate) fn validate_private_file(file: &File) -> io::Result<()> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::Authorization::GetSecurityInfo;
    use windows::Win32::Security::OWNER_SECURITY_INFORMATION;
    let sid = current_user_sid()?;
    let mut owner = PSID::default();
    let mut dacl = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: File owns the borrowed handle and output pointers refer to live locals.
    let status = unsafe {
        GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            Some(&raw mut dacl),
            None,
            Some(&raw mut descriptor),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(status_io_error(status));
    }
    let _descriptor = LocalMemory(descriptor.0);
    if owner.0.is_null() || dacl.is_null() || string_sid(owner)? != sid {
        return Err(io::Error::other(
            "file must be owned by the current user and have a private ACL",
        ));
    }
    if granted_trustees(dacl)?
        .iter()
        .any(|trustee| trustee != &sid)
    {
        return Err(io::Error::other("file grants access to another account"));
    }
    Ok(())
}

/// Set an explicit user owner (also for elevated tokens) and a protected DACL
/// granting that user full control over the directory and its children.
#[cfg(feature = "key-protection")]
fn owner_only_sddl(user_sid: &str) -> String {
    format!("O:{user_sid}D:P(A;OICI;FA;;;{user_sid})")
}

/// Map a Win32 failure to the `io::Error` `std::fs` would have produced, so
/// callers can keep matching on `ErrorKind::AlreadyExists`.
fn win32_io_error(error: &windows::core::Error) -> io::Error {
    let code = error.code().0.cast_unsigned();
    if code & 0xFFFF_0000 == 0x8007_0000 {
        i32::try_from(code & 0xFFFF).map_or_else(
            |_| io::Error::other(error.to_string()),
            io::Error::from_raw_os_error,
        )
    } else {
        io::Error::other(error.to_string())
    }
}

fn status_io_error(status: WIN32_ERROR) -> io::Error {
    i32::try_from(status.0).map_or_else(
        |_| io::Error::other(format!("Win32 error {}", status.0)),
        io::Error::from_raw_os_error,
    )
}

/// Create `root` with a protected DACL that only the current user can use.
/// Fails with `ErrorKind::AlreadyExists` when the directory is present, like
/// `fs::create_dir`.
#[cfg(feature = "key-protection")]
pub(crate) fn create_owner_only_directory(root: &Path) -> io::Result<()> {
    let sddl = HSTRING::from(owner_only_sddl(&current_user_sid()?).as_str());
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `sddl` is a NUL-terminated wide string for the duration of the
    // call, and `descriptor` receives a `LocalAlloc` buffer owned by the guard
    // below.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &sddl,
            SDDL_REVISION_1,
            &raw mut descriptor,
            None,
        )
    }
    .map_err(|error| {
        io::Error::other(format!(
            "could not build the vault root security descriptor: {error}"
        ))
    })?;
    let _descriptor = LocalMemory(descriptor.0);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>())
            .expect("SECURITY_ATTRIBUTES is a few machine words"),
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let path = HSTRING::from(root);
    // SAFETY: `path` and `attributes` outlive the call, and the descriptor
    // that `attributes` points to stays allocated until `_descriptor` drops.
    unsafe { CreateDirectoryW(&path, Some(&raw const attributes)) }
        .map_err(|error| win32_io_error(&error))
}

/// Reject `path` unless the current user owns it and its protected DACL grants
/// access to that user only.
#[cfg(feature = "key-protection")]
pub(crate) fn validate_owner_only_directory(path: &Path) -> io::Result<()> {
    let user_sid = current_user_sid().map_err(|error| io::Error::other(error.to_string()))?;
    let name = HSTRING::from(path);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: every out-pointer references a live local. The descriptor is a
    // `LocalAlloc` buffer owned by the guard below, which stays live through
    // descriptor validation.
    let status = unsafe {
        GetNamedSecurityInfoW(
            &name,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(permission_error(
            path,
            &format!(
                "could not read its permissions: {}",
                status_io_error(status)
            ),
        ));
    }
    let _descriptor = LocalMemory(descriptor.0);
    validate_directory_descriptor(path, &user_sid, descriptor)
}

#[cfg(feature = "key-protection")]
fn validate_directory_descriptor(
    path: &Path,
    user_sid: &str,
    descriptor: PSECURITY_DESCRIPTOR,
) -> io::Result<()> {
    let mut owner = PSID::default();
    let mut defaulted = windows::core::BOOL::default();
    // SAFETY: the caller keeps the queried/converted descriptor alive, and
    // every output points to a live local. Returned pointers borrow it.
    unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut defaulted) }
        .map_err(|error| win32_io_error(&error))?;
    if owner.0.is_null() || string_sid(owner)? != user_sid {
        return Err(permission_error(path, "must be owned by the current user"));
    }
    let mut dacl = ptr::null_mut();
    let mut present = windows::core::BOOL::default();
    // SAFETY: the descriptor and output pointers are live, as above.
    unsafe {
        GetSecurityDescriptorDacl(
            descriptor,
            &raw mut present,
            &raw mut dacl,
            &raw mut defaulted,
        )
    }
    .map_err(|error| win32_io_error(&error))?;
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: `descriptor` is a valid security descriptor until the guard
    // drops, and both out-pointers reference live locals.
    unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) }
        .map_err(|error| {
            permission_error(
                path,
                &format!("could not read its permission control flags: {error}"),
            )
        })?;
    if control & SE_DACL_PROTECTED.0 == 0 {
        return Err(permission_error(
            path,
            &format!(
                "inherits permissions from its parent directory; {}",
                repair_hint(path, user_sid)
            ),
        ));
    }
    if !present.as_bool() || dacl.is_null() {
        return Err(permission_error(
            path,
            &format!(
                "has no access control list, so every user can read it; {}",
                repair_hint(path, user_sid)
            ),
        ));
    }
    for trustee in granted_trustees(dacl)? {
        if trustee != user_sid {
            return Err(permission_error(
                path,
                &format!(
                    "grants access to `{trustee}` rather than only `{user_sid}`; {}",
                    repair_hint(path, user_sid)
                ),
            ));
        }
    }
    Ok(())
}

/// String SIDs of all allow entries, including inherited entries. Reject
/// unfamiliar ACE types rather than assuming they cannot widen access.
fn granted_trustees(dacl: *const ACL) -> io::Result<Vec<String>> {
    // SAFETY: callers supply an OS-owned ACL that lives throughout this call.
    if dacl.is_null() || !unsafe { IsValidAcl(dacl) }.as_bool() {
        return Err(io::Error::other("invalid vault access control list"));
    }
    let count = unsafe { (*dacl).AceCount };
    let mut trustees = Vec::with_capacity(usize::from(count));
    for index in 0..u32::from(count) {
        let mut entry = ptr::null_mut();
        // SAFETY: GetAce checks the index and returns storage in the live ACL.
        unsafe { GetAce(dacl, index, &raw mut entry) }.map_err(io::Error::other)?;
        let header = unsafe { &*entry.cast::<ACE_HEADER>() };
        match header.AceType {
            // ACCESS_ALLOWED_ACE_TYPE; SidStart is the first DWORD of the
            // variable-length SID in this OS-validated, DWORD-aligned ACE.
            0 => {
                let allow = entry.cast::<ACCESS_ALLOWED_ACE>();
                let sid = unsafe { &raw mut (*allow).SidStart };
                trustees.push(string_sid(PSID(sid.cast()))?);
            }
            // ACCESS_DENIED_ACE_TYPE cannot widen access.
            1 => {}
            _ => return Err(io::Error::other("unsupported vault access control entry")),
        }
    }
    Ok(trustees)
}

fn string_sid(sid: PSID) -> io::Result<String> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` points at a SID inside a live access control buffer, and
    // `text` receives a `LocalAlloc` string owned by the guard below.
    unsafe { ConvertSidToStringSidW(sid, &raw mut text) }.map_err(|error| {
        io::Error::other(format!(
            "could not format an access control trustee: {error}"
        ))
    })?;
    let _text = LocalMemory(text.0.cast());
    // SAFETY: `text` is a NUL-terminated wide string until the guard drops.
    unsafe { text.to_string() }.map_err(|error| {
        io::Error::other(format!(
            "access control trustee is not valid UTF-16: {error}"
        ))
    })
}

#[cfg(feature = "key-protection")]
fn repair_hint(path: &Path, user_sid: &str) -> String {
    format!(
        "run `icacls \"{}\" /inheritance:r /grant:r *{user_sid}:(OI)(CI)F` to make it private",
        path.display()
    )
}

#[cfg(feature = "key-protection")]
fn permission_error(path: &Path, detail: &str) -> io::Error {
    io::Error::other(format!("vault root `{}` {detail}", path.display()))
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "key-protection")]
    use std::fs;

    use super::*;

    #[test]
    #[ignore = "invoked by acceptance/windows-security.ps1 with an isolated fixture"]
    #[cfg(all(feature = "key-protection", feature = "transfer"))]
    fn create_two_account_fixture() {
        let parent =
            std::path::PathBuf::from(std::env::var_os("FACTORSEAL_SECURITY_FIXTURE").unwrap());
        let root = parent.join("vault");
        create_owner_only_directory(&root).unwrap();
        validate_owner_only_directory(&root).unwrap();
        for name in [
            "factorseal.json",
            "vault.db",
            "vault.db-wal",
            "vault.db-shm",
            "vault.lock",
        ] {
            fs::write(root.join(name), b"synthetic acceptance marker").unwrap();
        }
        crate::security::write_private_file(
            &parent.join("export.factorseal"),
            b"synthetic acceptance marker",
        )
        .unwrap();
    }

    #[test]
    #[cfg(feature = "key-protection")]
    fn directory_security_rejects_wrong_or_missing_owner_even_with_a_private_dacl() {
        let user_sid = current_user_sid().unwrap();
        for (owner, expected) in [
            (format!("O:{user_sid}"), true),
            ("O:WD".to_owned(), false),
            (String::new(), false),
        ] {
            let sddl = HSTRING::from(format!("{owner}D:P(A;OICI;FA;;;{user_sid})"));
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            // SAFETY: the string and output are live; LocalMemory owns the result.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    &sddl,
                    SDDL_REVISION_1,
                    &raw mut descriptor,
                    None,
                )
            }
            .unwrap();
            let _descriptor = LocalMemory(descriptor.0);
            let result =
                validate_directory_descriptor(Path::new("test-root"), &user_sid, descriptor);
            if expected {
                result.unwrap();
            } else {
                assert!(
                    result
                        .unwrap_err()
                        .to_string()
                        .contains("must be owned by the current user")
                );
            }
        }
    }

    #[test]
    #[cfg(feature = "key-protection")]
    fn vault_children_inherit_private_access_under_a_shared_parent() {
        let directory = tempfile::tempdir().unwrap();
        assert!(
            std::process::Command::new("icacls")
                .arg(directory.path())
                .args(["/grant", "*S-1-1-0:(OI)(CI)F"])
                .output()
                .unwrap()
                .status
                .success()
        );
        let root = directory.path().join("vault");
        create_owner_only_directory(&root).unwrap();
        validate_owner_only_directory(&root).unwrap();
        // Exercise ordinary child creation, as used by metadata and database
        // files, rather than assigning explicit private permissions to them.
        for name in [
            "factorseal.json",
            "vault.db",
            "vault.db-wal",
            "vault.db-shm",
            "vault.lock",
        ] {
            let path = root.join(name);
            fs::write(&path, b"private").unwrap();
            let mut dacl = ptr::null_mut();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            // SAFETY: outputs are live and LocalMemory owns the returned descriptor.
            let status = unsafe {
                GetNamedSecurityInfoW(
                    &HSTRING::from(path.as_path()),
                    SE_FILE_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    None,
                    None,
                    Some(&raw mut dacl),
                    None,
                    &raw mut descriptor,
                )
            };
            assert_eq!(status, ERROR_SUCCESS);
            let _descriptor = LocalMemory(descriptor.0);
            assert!(!dacl.is_null());
            assert_eq!(
                granted_trustees(dacl).unwrap(),
                [current_user_sid().unwrap()]
            );
        }
    }

    #[test]
    #[cfg(feature = "key-protection")]
    fn owner_only_sddl_grants_full_control_to_one_protected_trustee() {
        assert_eq!(
            owner_only_sddl("S-1-5-21-1-2-3-1001"),
            "O:S-1-5-21-1-2-3-1001D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
    #[cfg(feature = "key-protection")]
    fn a_created_root_validates_and_an_inherited_directory_does_not() {
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private");
        create_owner_only_directory(&private).unwrap();
        validate_owner_only_directory(&private).unwrap();
        assert_eq!(
            create_owner_only_directory(&private).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );

        let inherited = directory.path().join("inherited");
        fs::create_dir(&inherited).unwrap();
        assert!(validate_owner_only_directory(&inherited).is_err());
    }

    #[cfg(any(feature = "transfer", feature = "personal-sync"))]
    #[test]
    fn exports_remain_private_in_shared_directories_and_after_replacement() {
        use crate::security::{read_private_file, write_private_file};
        fn grant(path: &Path, permission: &str) {
            assert!(
                std::process::Command::new("icacls")
                    .arg(path)
                    .args(["/grant", permission])
                    .output()
                    .unwrap()
                    .status
                    .success()
            );
        }
        let directory = tempfile::tempdir().unwrap();
        grant(directory.path(), "*S-1-1-0:(OI)(CI)F");
        let path = directory.path().join("export");
        write_private_file(&path, b"secret").unwrap();
        assert_eq!(&**read_private_file(&path, 6).unwrap(), b"secret");
        // Existing broad grants must be rejected on input and removed by output replacement.
        grant(&path, "*S-1-1-0:R");
        assert!(read_private_file(&path, 6).is_err());
        write_private_file(&path, b"replacement").unwrap();
        assert_eq!(&**read_private_file(&path, 11).unwrap(), b"replacement");
        assert!(read_private_file(&path, 10).is_err());
    }
}

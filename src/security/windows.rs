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
#[cfg(feature = "transfer")]
use std::{
    fs::File,
    os::windows::io::{AsRawHandle, FromRawHandle},
};
use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree, WIN32_ERROR};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetExplicitEntriesFromAclW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SET_ACCESS, TRUSTEE_IS_SID,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, TOKEN_QUERY,
};
#[cfg(feature = "key-protection")]
use windows::Win32::{
    Security::{
        Authorization::GetNamedSecurityInfoW, GetSecurityDescriptorControl, SE_DACL_PROTECTED,
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
#[cfg(feature = "transfer")]
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
#[cfg(feature = "transfer")]
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

/// SDDL for a protected DACL that grants `user_sid` full control over the
/// directory and everything created inside it, and nothing to anyone else.
#[cfg(feature = "key-protection")]
fn owner_only_sddl(user_sid: &str) -> String {
    format!("D:P(A;OICI;FA;;;{user_sid})")
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

/// Reject `path` unless its DACL is protected from inheritance and grants
/// access to the current user only.
#[cfg(feature = "key-protection")]
pub(crate) fn validate_owner_only_directory(path: &Path) -> io::Result<()> {
    let user_sid = current_user_sid().map_err(|error| io::Error::other(error.to_string()))?;
    let name = HSTRING::from(path);
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: every out-pointer references a live local. The descriptor is a
    // `LocalAlloc` buffer owned by the guard below, and `dacl` points inside
    // it, so both stay valid until the guard drops.
    let status = unsafe {
        GetNamedSecurityInfoW(
            &name,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&raw mut dacl),
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
                repair_hint(path, &user_sid)
            ),
        ));
    }
    if dacl.is_null() {
        return Err(permission_error(
            path,
            &format!(
                "has no access control list, so every user can read it; {}",
                repair_hint(path, &user_sid)
            ),
        ));
    }
    for trustee in granted_trustees(dacl)? {
        if trustee != user_sid {
            return Err(permission_error(
                path,
                &format!(
                    "grants access to `{trustee}` rather than only `{user_sid}`; {}",
                    repair_hint(path, &user_sid)
                ),
            ));
        }
    }
    Ok(())
}

/// String SIDs of every trustee that `dacl` grants access to. Deny and audit
/// entries never widen access, so they are skipped.
fn granted_trustees(dacl: *const ACL) -> io::Result<Vec<String>> {
    let mut count = 0_u32;
    let mut entries: *mut EXPLICIT_ACCESS_W = ptr::null_mut();
    // SAFETY: `dacl` is valid for the caller's descriptor lifetime and both
    // out-pointers reference live locals; `entries` receives a `LocalAlloc`
    // buffer owned by the guard below.
    let status = unsafe { GetExplicitEntriesFromAclW(dacl, &raw mut count, &raw mut entries) };
    if status != ERROR_SUCCESS {
        return Err(io::Error::other(format!(
            "could not enumerate the vault root access control entries: {}",
            status_io_error(status)
        )));
    }
    let _entries = LocalMemory(entries.cast());
    let count = usize::try_from(count).map_err(|_| {
        io::Error::other("vault root access control entry count is invalid".to_owned())
    })?;
    let entries: &[EXPLICIT_ACCESS_W] = if entries.is_null() || count == 0 {
        &[]
    } else {
        // SAFETY: the call reported `count` initialized entries at `entries`,
        // which stay allocated until the guard drops.
        unsafe { std::slice::from_raw_parts(entries.cast_const(), count) }
    };
    let mut trustees = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.grfAccessMode != GRANT_ACCESS && entry.grfAccessMode != SET_ACCESS {
            continue;
        }
        if entry.Trustee.TrusteeForm != TRUSTEE_IS_SID {
            return Err(io::Error::other(
                "vault root grants access to a trustee that is not a SID".to_owned(),
            ));
        }
        trustees.push(string_sid(PSID(entry.Trustee.ptstrName.0.cast()))?);
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
    #[cfg(feature = "key-protection")]
    fn owner_only_sddl_grants_full_control_to_one_protected_trustee() {
        assert_eq!(
            owner_only_sddl("S-1-5-21-1-2-3-1001"),
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"
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

    #[cfg(feature = "transfer")]
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

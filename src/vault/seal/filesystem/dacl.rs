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
use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree, WIN32_ERROR};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, GetExplicitEntriesFromAclW, GetNamedSecurityInfoW,
    SDDL_REVISION_1, SE_FILE_OBJECT, SET_ACCESS, TRUSTEE_IS_SID,
};
use windows::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorControl, PSECURITY_DESCRIPTOR, PSID,
    SE_DACL_PROTECTED, SECURITY_ATTRIBUTES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::core::{HSTRING, PWSTR};

use crate::vault::{VaultError, VaultResult};

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

/// SDDL for a protected DACL that grants `user_sid` full control over the
/// directory and everything created inside it, and nothing to anyone else.
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
pub(super) fn create_owner_only_directory(root: &Path) -> io::Result<()> {
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
pub(super) fn validate_owner_only_directory(path: &Path) -> VaultResult<()> {
    let user_sid = current_user_sid().map_err(|error| VaultError::Protection(error.to_string()))?;
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
fn granted_trustees(dacl: *const ACL) -> VaultResult<Vec<String>> {
    let mut count = 0_u32;
    let mut entries: *mut EXPLICIT_ACCESS_W = ptr::null_mut();
    // SAFETY: `dacl` is valid for the caller's descriptor lifetime and both
    // out-pointers reference live locals; `entries` receives a `LocalAlloc`
    // buffer owned by the guard below.
    let status = unsafe { GetExplicitEntriesFromAclW(dacl, &raw mut count, &raw mut entries) };
    if status != ERROR_SUCCESS {
        return Err(VaultError::Protection(format!(
            "could not enumerate the vault root access control entries: {}",
            status_io_error(status)
        )));
    }
    let _entries = LocalMemory(entries.cast());
    let count = usize::try_from(count).map_err(|_| {
        VaultError::Protection("vault root access control entry count is invalid".to_owned())
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
            return Err(VaultError::Protection(
                "vault root grants access to a trustee that is not a SID".to_owned(),
            ));
        }
        trustees.push(string_sid(PSID(entry.Trustee.ptstrName.0.cast()))?);
    }
    Ok(trustees)
}

fn string_sid(sid: PSID) -> VaultResult<String> {
    let mut text = PWSTR::null();
    // SAFETY: `sid` points at a SID inside a live access control buffer, and
    // `text` receives a `LocalAlloc` string owned by the guard below.
    unsafe { ConvertSidToStringSidW(sid, &raw mut text) }.map_err(|error| {
        VaultError::Protection(format!(
            "could not format an access control trustee: {error}"
        ))
    })?;
    let _text = LocalMemory(text.0.cast());
    // SAFETY: `text` is a NUL-terminated wide string until the guard drops.
    unsafe { text.to_string() }.map_err(|error| {
        VaultError::Protection(format!(
            "access control trustee is not valid UTF-16: {error}"
        ))
    })
}

fn repair_hint(path: &Path, user_sid: &str) -> String {
    format!(
        "run `icacls \"{}\" /inheritance:r /grant:r *{user_sid}:(OI)(CI)F` to make it private",
        path.display()
    )
}

fn permission_error(path: &Path, detail: &str) -> VaultError {
    VaultError::Protection(format!("vault root `{}` {detail}", path.display()))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn owner_only_sddl_grants_full_control_to_one_protected_trustee() {
        assert_eq!(
            owner_only_sddl("S-1-5-21-1-2-3-1001"),
            "D:P(A;OICI;FA;;;S-1-5-21-1-2-3-1001)"
        );
    }

    #[test]
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
}

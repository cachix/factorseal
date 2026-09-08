//! LPAC is identified by the kernel's WIN://NOALLAPPPKG security attribute.
//! TokenIsLessPrivilegedAppContainer is present in the SDK but the native
//! query returns STATUS_INVALID_INFO_CLASS on supported Windows runners.
//! See System Informer phlib/nativetoken.c and NtCoreLib/NtToken.cs.
use std::{ffi::c_void, io, mem::size_of};
use windows::Win32::Foundation::{HANDLE, NTSTATUS, UNICODE_STRING};
use windows::core::{HSTRING, PWSTR};

#[repr(C)]
#[derive(Clone, Copy)]
struct Attributes {
    version: u16,
    reserved: u16,
    count: u32,
    entries: *const Attribute,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Attribute {
    name: UNICODE_STRING,
    value_type: u16,
    reserved: u16,
    flags: u32,
    count: u32,
    values: *const u64,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtQuerySecurityAttributesToken(
        token: HANDLE,
        names: *const UNICODE_STRING,
        count: u32,
        output: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> NTSTATUS;
}

pub(super) fn enabled(token: HANDLE) -> io::Result<bool> {
    let name = HSTRING::from("WIN://NOALLAPPPKG");
    let length = u16::try_from(name.len() * 2).expect("fixed attribute name");
    let query = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: PWSTR(name.as_ptr().cast_mut()),
    };
    // One fixed-name scalar attribute fits comfortably in this aligned buffer.
    // Unknown larger representations fail closed instead of changing policy.
    let mut buffer = [0_u64; 64];
    let mut returned = 0;
    let status = unsafe {
        NtQuerySecurityAttributesToken(
            token,
            &raw const query,
            1,
            buffer.as_mut_ptr().cast(),
            u32::try_from(size_of_val(&buffer)).expect("fixed buffer"),
            &raw mut returned,
        )
    };
    if status.0 < 0 {
        return Err(io::Error::other(format!(
            "query LPAC security attribute: NTSTATUS {:#010x}",
            status.0
        )));
    }
    if returned as usize > size_of_val(&buffer) || (returned as usize) < size_of::<Attributes>() {
        return Err(invalid());
    }
    let header = checked(
        &buffer,
        returned as usize,
        buffer.as_ptr().cast::<Attributes>(),
        1,
    )?[0];
    if header.version != 1 || header.count != 1 {
        return Ok(false);
    }
    let attribute = checked(&buffer, returned as usize, header.entries, 1)?[0];
    if attribute.value_type != 2 || attribute.count != 1 || attribute.flags & 0x10 != 0 {
        return Ok(false);
    }
    if attribute.name.Length != length || attribute.name.MaximumLength < length {
        return Ok(false);
    }
    let actual_name = checked(
        &buffer,
        returned as usize,
        attribute.name.Buffer.0,
        name.len(),
    )?;
    if actual_name != &*name {
        return Ok(false);
    }
    Ok(checked(&buffer, returned as usize, attribute.values, 1)?[0] != 0)
}

fn checked<T>(buffer: &[u64], length: usize, pointer: *const T, count: usize) -> io::Result<&[T]> {
    let start = buffer.as_ptr() as usize;
    let offset = (pointer as usize).checked_sub(start).ok_or_else(invalid)?;
    let end = count
        .checked_mul(size_of::<T>())
        .and_then(|size| offset.checked_add(size))
        .ok_or_else(invalid)?;
    if end > length || !pointer.is_aligned() {
        return Err(invalid());
    }
    // SAFETY: the successful kernel query initialized these ABI structures
    // within our aligned output. Their complete ranges are checked above.
    Ok(unsafe { std::slice::from_raw_parts(pointer, count) })
}

fn invalid() -> io::Error {
    io::Error::other("invalid LPAC security attribute")
}

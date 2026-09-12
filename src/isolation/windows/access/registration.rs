//! Identity registration without AppContainer profile storage. Chromium uses
//! these kernelbase exports separately from profile-directory creation:
//! sandbox/win/src/app_container_base.cc.
use super::{Sid, error};
use std::io;
use windows::Win32::{
    Security::PSID,
    System::LibraryLoader::{GetModuleHandleW, GetProcAddress},
};
use windows::core::{HRESULT, HSTRING, PCWSTR, s, w};

type Entry = unsafe extern "system" fn() -> isize;
type Register = unsafe extern "system" fn(PSID, PCWSTR, PCWSTR) -> HRESULT;
type Unregister = unsafe extern "system" fn(PSID) -> HRESULT;

pub(super) struct Registration {
    sid: Sid,
    unregister: Unregister,
}

impl Registration {
    pub(super) fn new(sid: &Sid, name: &HSTRING) -> io::Result<Self> {
        let sid = Sid::copy(sid.raw())?;
        let module = unsafe { GetModuleHandleW(w!("kernelbase.dll")) }.map_err(error)?;
        let register = unsafe { GetProcAddress(module, s!("AppContainerRegisterSid")) }
            .ok_or_else(|| io::Error::other("AppContainer registration is unavailable"))?;
        let unregister = unsafe { GetProcAddress(module, s!("AppContainerUnregisterSid")) }
            .ok_or_else(|| io::Error::other("AppContainer deregistration is unavailable"))?;
        // SAFETY: exact system ABI signatures used by Chromium. kernelbase
        // stays loaded for the process lifetime. Resolve both exports before
        // creating state, and fail closed if either operation is unavailable.
        let register = unsafe { std::mem::transmute::<Entry, Register>(register) };
        let unregister = unsafe { std::mem::transmute::<Entry, Unregister>(unregister) };
        unsafe { register(sid.raw(), PCWSTR(name.as_ptr()), PCWSTR(name.as_ptr())) }
            .ok()
            .map_err(error)?;
        Ok(Self { sid, unregister })
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        let _ = unsafe { (self.unregister)(self.sid.raw()) };
    }
}

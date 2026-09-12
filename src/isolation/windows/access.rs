use super::error;
use nt_token::OwnedToken;
use std::{ffi::c_void, io};
use windows::Win32::{
    Foundation::{HLOCAL, LocalFree},
    Security::{
        Authorization::ConvertSidToStringSidW, CopySid, DeriveCapabilitySidsFromName, GetLengthSid,
        IsValidSid, PSID, TOKEN_QUERY,
    },
};
use windows::core::{HSTRING, PWSTR};
mod lpac;

// These grants cover IP transport and platform certificate validation. No
// identity/enterprise-authentication or credential-broker capability is given.
const NETWORK_CAPABILITIES: &[&str] = &[
    "internetClientServer",
    "privateNetworkClientServer",
    "registryRead",
    "lpacCryptoServices",
];

#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
mod launch;
#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
mod registration;
#[cfg(any(feature = "vault", feature = "personal-sync-network"))]
pub(super) use launch::Identity;

pub(super) struct Sid(Vec<u32>);
impl Sid {
    pub(super) fn raw(&self) -> PSID {
        PSID(self.0.as_ptr().cast_mut().cast())
    }
    fn copy(sid: PSID) -> io::Result<Self> {
        if !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(io::Error::other("invalid sandbox SID"));
        }
        let bytes = unsafe { GetLengthSid(sid) };
        if bytes == 0 || bytes > 1024 {
            return Err(io::Error::other("sandbox SID size is invalid"));
        }
        let owned = Self(vec![0; (bytes as usize).div_ceil(4)]);
        unsafe { CopySid(bytes, owned.raw(), sid) }.map_err(error)?;
        Ok(owned)
    }
    fn capability(name: &str) -> io::Result<Self> {
        let (mut groups, mut capabilities) = (std::ptr::null_mut(), std::ptr::null_mut());
        let (mut group_count, mut count) = (0, 0);
        unsafe {
            DeriveCapabilitySidsFromName(
                &HSTRING::from(name),
                &raw mut groups,
                &raw mut group_count,
                &raw mut capabilities,
                &raw mut count,
            )
        }
        .map_err(error)?;
        let result = if count == 1 {
            Self::copy(unsafe { *capabilities })
        } else {
            Err(io::Error::other("ambiguous sandbox capability"))
        };
        // All nested SIDs and both arrays are separate LocalAlloc allocations.
        for index in 0..group_count {
            unsafe {
                LocalFree(Some(HLOCAL((*groups.add(index as usize)).0)));
            }
        }
        for index in 0..count {
            unsafe {
                LocalFree(Some(HLOCAL((*capabilities.add(index as usize)).0)));
            }
        }
        unsafe {
            LocalFree(Some(HLOCAL(groups.cast())));
            LocalFree(Some(HLOCAL(capabilities.cast())));
        }
        result
    }
    fn string(&self) -> io::Result<String> {
        string(self.raw())
    }
}

struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(Some(HLOCAL(self.0)));
        }
    }
}

fn string(sid: PSID) -> io::Result<String> {
    let mut text = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &raw mut text) }.map_err(error)?;
    let _text = Local(text.0.cast());
    unsafe { text.to_string() }.map_err(io::Error::other)
}

#[cfg(any(feature = "key-protection", feature = "transfer"))]
pub(crate) fn current_app_sid() -> io::Result<Option<String>> {
    let token = OwnedToken::from_current_process(TOKEN_QUERY).map_err(error)?;
    token
        .app_container_sid()
        .map_err(error)?
        .map(|sid| sid.to_string().map_err(error))
        .transpose()
}

pub(super) fn verify(network: bool) -> io::Result<()> {
    let token = OwnedToken::from_current_process(TOKEN_QUERY).map_err(error)?;
    if !token
        .is_app_container()
        .map_err(|error| io::Error::other(format!("query AppContainer token status: {error}")))?
        || !lpac::enabled(token.handle())?
    {
        return Err(io::Error::other(
            "helper requires a less-privileged AppContainer",
        ));
    }
    let mut actual = token
        .capabilities()
        .map_err(|error| io::Error::other(format!("query token capabilities: {error}")))?
        .into_iter()
        .map(|group| group.sid().to_string().map_err(error))
        .collect::<io::Result<Vec<_>>>()?;
    let mut expected = if network {
        NETWORK_CAPABILITIES
            .iter()
            .map(|name| Sid::capability(name)?.string())
            .collect::<io::Result<Vec<_>>>()?
    } else {
        Vec::new()
    };
    actual.sort();
    expected.sort();
    if actual != expected {
        return Err(io::Error::other("helper has unexpected capabilities"));
    }
    Ok(())
}

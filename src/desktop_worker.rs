//! Bounded bootstrap messages carried only over inherited private pipes.
//! Factors are never command-line arguments, environment variables, or files.

use crate::{UnlockGroup, UnlockPolicy, WireSecret};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[cfg(feature = "personal-sync")]
pub mod sync;

const MAX_BOOTSTRAP_BYTES: usize = 128 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub desktop_executable: PathBuf,
    pub operation: Operation,
    pub password: WireSecret,
    /// The Desktop serves `org.freedesktop.secrets` itself and needs the
    /// adapter grant; the worker then leaves the session bus to it.
    #[serde(default)]
    pub hosts_secret_service: bool,
    #[serde(default)]
    pub sync_control: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum Operation {
    /// Authenticate and sign approvals without opening or serving the database.
    SignPermissions {
        group: UnlockGroup,
        requests: Vec<(String, [u8; 32], Option<u64>)>,
    },
    Initialize {
        policy: UnlockPolicy,
    },
    Unlock {
        group: UnlockGroup,
        idle_seconds: u64,
        maximum_seconds: u64,
    },
}

/// Send one bounded message; serialized factors are wiped after delivery.
pub fn send(writer: &mut impl Write, message: &impl Serialize) -> io::Result<()> {
    let bytes = crate::security::memory::serialize_locked(message, MAX_BOOTSTRAP_BYTES)
        .map_err(io::Error::other)?;
    crate::security::frame::write(writer, &bytes, MAX_BOOTSTRAP_BYTES)
}

/// Read exactly one frame, leaving the pipe available as the parent lifeline.
pub fn receive<T: serde::de::DeserializeOwned>(reader: &mut impl Read) -> io::Result<T> {
    let bytes = crate::security::frame::read(reader, MAX_BOOTSTRAP_BYTES)?;
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frames_are_bounded_and_leave_the_lifeline_unread() {
        let mut bytes = Vec::new();
        send(&mut bytes, &Ok::<_, String>(())).unwrap();
        bytes.push(42);
        let mut input = bytes.as_slice();
        assert!(receive::<Result<(), String>>(&mut input).unwrap().is_ok());
        assert_eq!(input, &[42]);
        assert!(receive::<Bootstrap>(&mut &u32::MAX.to_be_bytes()[..]).is_err());
        assert!(receive::<Bootstrap>(&mut &[0, 0, 0, 10, 1][..]).is_err());
    }
}

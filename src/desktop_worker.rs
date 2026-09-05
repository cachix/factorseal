//! Bounded bootstrap messages carried only over inherited private pipes.
//! Factors are never command-line arguments, environment variables, or files.

use crate::{UnlockGroup, UnlockPolicy, WireSecret};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use zeroize::Zeroizing;

const MAX_BOOTSTRAP_BYTES: usize = 128 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap {
    pub desktop_executable: PathBuf,
    pub operation: Operation,
    pub password: WireSecret,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum Operation {
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
    let bytes = Zeroizing::new(serde_json::to_vec(message)?);
    if bytes.is_empty() || bytes.len() > MAX_BOOTSTRAP_BYTES {
        return Err(io::Error::other("invalid desktop worker message length"));
    }
    let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()
}

/// Read exactly one frame, leaving the pipe available as the parent lifeline.
pub fn receive<T: serde::de::DeserializeOwned>(reader: &mut impl Read) -> io::Result<T> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_BOOTSTRAP_BYTES {
        return Err(io::Error::other("invalid desktop worker message length"));
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    reader.read_exact(&mut bytes)?;
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

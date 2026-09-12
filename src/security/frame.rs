//! Length-prefixed frames read into locked memory over blocking streams.
//!
//! The isolated helpers and the Desktop bootstrap pipe carry the same shape:
//! a big-endian `u32` length, bounded by the caller, followed by the payload.
//! The bounded nonblocking variant used by the vault endpoint lives in the
//! vault transport; this one is for inherited private pipes that block.

// Compiled only where a user exists: the Desktop bootstrap pipe and the
// isolated helper codec. A client-only build has neither.
#![cfg(any(
    all(feature = "vault-client", feature = "key-protection"),
    feature = "helper-isolation"
))]

use super::LockedBytes;
use std::io::{self, Read, Write};

/// Read exactly one frame of at most `maximum` bytes, leaving the stream
/// positioned after it. The payload never lives in unlocked memory.
pub(crate) fn read(reader: &mut impl Read, maximum: usize) -> io::Result<LockedBytes> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > maximum {
        return Err(io::Error::other("invalid frame length"));
    }
    let mut bytes = LockedBytes::zeroed(length).map_err(io::Error::other)?;
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Write one frame of at most `maximum` bytes and flush it.
pub(crate) fn write(writer: &mut impl Write, bytes: &[u8], maximum: usize) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(io::Error::other("invalid frame length"));
    }
    let length = u32::try_from(bytes.len()).map_err(io::Error::other)?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(bytes)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_are_bounded_and_leave_following_bytes_unread() {
        let mut wire = Vec::new();
        write(&mut wire, b"payload", 16).unwrap();
        wire.push(42);
        let mut input = wire.as_slice();
        assert_eq!(read(&mut input, 16).unwrap().as_slice(), b"payload");
        assert_eq!(input, &[42]);
        assert!(write(&mut Vec::new(), b"", 16).is_err());
        assert!(write(&mut Vec::new(), b"too long for it", 4).is_err());
        assert!(read(&mut &u32::MAX.to_be_bytes()[..], 16).is_err());
        assert!(read(&mut &[0, 0, 0, 10, 1][..], 16).is_err());
        assert!(read(&mut &[0, 0, 0, 0][..], 16).is_err());
    }
}

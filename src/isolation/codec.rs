use crate::security::LockedBytes;
use serde::Serialize;
#[cfg(any(test, feature = "vault", feature = "personal-sync-network"))]
use serde::de::DeserializeOwned;
use std::io::{self, Read, Write};

/// Serialize into an exactly sized locked allocation. Helpers never turn a
/// size bound into an unbounded temporary Vec of secret values.
pub(super) fn encode(value: &impl Serialize, maximum: usize) -> io::Result<LockedBytes> {
    crate::security::memory::serialize_locked_with(maximum, |writer| {
        ciborium::ser::into_writer(value, writer).map_err(io::Error::other)
    })
    .map_err(io::Error::other)
}

#[cfg(any(test, feature = "vault", feature = "personal-sync-network"))]
pub(super) fn decode<T: DeserializeOwned>(mut bytes: &[u8], maximum: usize) -> io::Result<T> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(io::Error::other("invalid helper message size"));
    }
    let mut inspected = bytes;
    check_item(&mut inspected, 0)?;
    if !inspected.is_empty() {
        return Err(io::Error::other("trailing helper message data"));
    }
    // Ciborium's default scratch buffer is on the stack and large strings use
    // temporary heap allocations. Our definite-length subset and full-frame
    // locked scratch prevent either from holding unprotected secret strings.
    let mut scratch = LockedBytes::zeroed(bytes.len()).map_err(io::Error::other)?;
    let value = ciborium::de::from_reader_with_buffer(&mut bytes, &mut scratch)
        .map_err(io::Error::other)?;
    if !bytes.is_empty() {
        return Err(io::Error::other("trailing helper message data"));
    }
    Ok(value)
}

/// Check structure without allocating from any attacker-supplied length. The
/// serializer emits only definite-length items. This also caps nesting before
/// serde visits a collection or reserves memory for it.
#[cfg(any(test, feature = "vault", feature = "personal-sync-network"))]
fn check_item(bytes: &mut &[u8], depth: usize) -> io::Result<()> {
    if depth >= 64 {
        return Err(io::Error::other("helper nesting exceeds limit"));
    }
    let header = take(bytes, 1)?[0];
    let argument = match header & 31 {
        value @ 0..=23 => u64::from(value),
        24 => u64::from(take(bytes, 1)?[0]),
        25 => u64::from(u16::from_be_bytes(
            take(bytes, 2)?.try_into().expect("fixed length"),
        )),
        26 => u64::from(u32::from_be_bytes(
            take(bytes, 4)?.try_into().expect("fixed length"),
        )),
        27 => u64::from_be_bytes(take(bytes, 8)?.try_into().expect("fixed length")),
        _ => return Err(io::Error::other("indefinite or reserved helper item")),
    };
    match header >> 5 {
        2 | 3 => {
            take(bytes, usize::try_from(argument).map_err(io::Error::other)?)?;
        }
        major @ (4 | 5) => {
            let count = if major == 5 {
                argument
                    .checked_mul(2)
                    .ok_or_else(|| io::Error::other("helper map is too large"))?
            } else {
                argument
            };
            let count = usize::try_from(count).map_err(io::Error::other)?;
            if count > bytes.len() {
                return Err(io::Error::other("truncated helper collection"));
            }
            for _ in 0..count {
                check_item(bytes, depth + 1)?;
            }
        }
        6 => check_item(bytes, depth + 1)?,
        _ => {}
    }
    Ok(())
}

#[cfg(any(test, feature = "vault", feature = "personal-sync-network"))]
fn take<'a>(bytes: &mut &'a [u8], count: usize) -> io::Result<&'a [u8]> {
    let (taken, rest) = bytes
        .split_at_checked(count)
        .ok_or_else(|| io::Error::other("truncated helper item"))?;
    *bytes = rest;
    Ok(taken)
}

pub(super) fn read(reader: &mut impl Read, maximum: usize) -> io::Result<LockedBytes> {
    crate::security::frame::read(reader, maximum)
}

pub(super) fn send(
    writer: &mut impl Write,
    value: &impl Serialize,
    maximum: usize,
) -> io::Result<()> {
    crate::security::frame::write(writer, &encode(value, maximum)?, maximum)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cbor_rejects_oversized_trailing_and_deep_messages() {
        let value = vec!["hello".to_owned()];
        let bytes = encode(&value, 64).unwrap();
        assert_eq!(decode::<Vec<String>>(&bytes, 64).unwrap(), value);
        assert!(encode(&value, 2).is_err());
        let mut extra = bytes.to_vec();
        extra.push(0);
        assert!(decode::<Vec<String>>(&extra, 64).is_err());
        assert!(decode::<Vec<String>>(&bytes, 2).is_err());
        let mut deep = vec![0x81; 128];
        deep.push(0);
        assert!(decode::<ciborium::Value>(&deep, 1024).is_err());
        assert!(decode::<String>(&[0x7f, 0x61, b'x', 0xff], 64).is_err());
        assert!(
            decode::<Vec<u8>>(&[0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 64).is_err()
        );
        let secret = "x".repeat(8192);
        let bytes = encode(&secret, 16384).unwrap();
        assert_eq!(decode::<String>(&bytes, 16384).unwrap(), secret);
    }
}

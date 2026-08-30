//! Envelope format shared by the Linux and Windows TPM transports.
//!
//! Both platforms seal through the same TPM 2.0 codec and emit the same
//! `HSEALTPM` envelope, so the wire format is defined once here instead of
//! being maintained separately alongside each transport.

use crate::{AccessPolicy, Error, LABEL_HASH_BYTES};

const MAGIC: &[u8; 8] = b"HSEALTPM";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 1 + LABEL_HASH_BYTES + 4 + 4;
pub(super) const MAX_BLOB_BYTES: usize = 16 * 1024;

pub(super) fn encode(
    policy: AccessPolicy,
    label_hash: [u8; LABEL_HASH_BYTES],
    public_blob: &[u8],
    private_blob: &[u8],
) -> Result<Vec<u8>, Error> {
    let public_len = u32::try_from(public_blob.len())
        .map_err(|_| Error::InvalidEnvelope("TPM public blob is too large".to_owned()))?;
    let private_len = u32::try_from(private_blob.len())
        .map_err(|_| Error::InvalidEnvelope("TPM private blob is too large".to_owned()))?;
    let mut output = Vec::with_capacity(HEADER_BYTES + public_blob.len() + private_blob.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.push(policy_id(policy));
    output.extend_from_slice(&label_hash);
    output.extend_from_slice(&public_len.to_be_bytes());
    output.extend_from_slice(&private_len.to_be_bytes());
    output.extend_from_slice(public_blob);
    output.extend_from_slice(private_blob);
    Ok(output)
}

pub(super) struct Parsed<'a> {
    pub(super) policy: AccessPolicy,
    pub(super) label_hash: [u8; LABEL_HASH_BYTES],
    pub(super) public_blob: &'a [u8],
    pub(super) private_blob: &'a [u8],
}

pub(super) fn parse(input: &[u8]) -> Result<Parsed<'_>, Error> {
    if input.len() < HEADER_BYTES || &input[..MAGIC.len()] != MAGIC {
        return Err(Error::InvalidEnvelope(
            "missing hardwareseal envelope header".to_owned(),
        ));
    }
    if input[MAGIC.len()] != VERSION {
        return Err(Error::InvalidEnvelope(format!(
            "unsupported envelope version {}",
            input[MAGIC.len()]
        )));
    }
    let policy = policy_from_id(input[MAGIC.len() + 1])?;
    let mut offset = MAGIC.len() + 2;
    let mut label_hash = [0; LABEL_HASH_BYTES];
    label_hash.copy_from_slice(&input[offset..offset + LABEL_HASH_BYTES]);
    offset += LABEL_HASH_BYTES;
    let public_len = read_length(input, &mut offset)?;
    let private_len = read_length(input, &mut offset)?;
    if public_len > MAX_BLOB_BYTES || private_len > MAX_BLOB_BYTES {
        return Err(Error::InvalidEnvelope(
            "TPM blob exceeds the envelope size limit".to_owned(),
        ));
    }
    let expected = offset
        .checked_add(public_len)
        .and_then(|length| length.checked_add(private_len))
        .ok_or_else(|| Error::InvalidEnvelope("envelope length overflow".to_owned()))?;
    if expected != input.len() {
        return Err(Error::InvalidEnvelope(
            "envelope lengths do not match its contents".to_owned(),
        ));
    }
    let public_end = offset + public_len;
    Ok(Parsed {
        policy,
        label_hash,
        public_blob: &input[offset..public_end],
        private_blob: &input[public_end..],
    })
}

pub(super) fn read_length(input: &[u8], offset: &mut usize) -> Result<usize, Error> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::InvalidEnvelope("envelope length overflow".to_owned()))?;
    let bytes = input
        .get(*offset..end)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| Error::InvalidEnvelope("truncated envelope lengths".to_owned()))?;
    *offset = end;
    Ok(u32::from_be_bytes(bytes) as usize)
}

pub(super) const fn policy_id(policy: AccessPolicy) -> u8 {
    match policy {
        AccessPolicy::None => 0,
        AccessPolicy::Biometric => 1,
    }
}

fn policy_from_id(id: u8) -> Result<AccessPolicy, Error> {
    match id {
        0 => Ok(AccessPolicy::None),
        1 => Ok(AccessPolicy::Biometric),
        _ => Err(Error::InvalidEnvelope(format!(
            "unknown access policy identifier {id}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let label_hash = [7; LABEL_HASH_BYTES];
        let encoded =
            encode(AccessPolicy::None, label_hash, b"public", b"private").expect("encode");
        let parsed = parse(&encoded).expect("parse");
        assert_eq!(parsed.policy, AccessPolicy::None);
        assert_eq!(parsed.label_hash, label_hash);
        assert_eq!(parsed.public_blob, b"public");
        assert_eq!(parsed.private_blob, b"private");
    }

    #[test]
    fn envelope_rejects_trailing_data() {
        let mut encoded = encode(
            AccessPolicy::None,
            [7; LABEL_HASH_BYTES],
            b"public",
            b"private",
        )
        .expect("encode");
        encoded.push(0);
        assert!(parse(&encoded).is_err());
    }

    #[test]
    fn envelope_rejects_oversized_blob_lengths() {
        let mut encoded = encode(
            AccessPolicy::None,
            [7; LABEL_HASH_BYTES],
            b"public",
            b"private",
        )
        .expect("encode");
        let public_len_offset = MAGIC.len() + 2 + LABEL_HASH_BYTES;
        let oversized = u32::try_from(MAX_BLOB_BYTES + 1).expect("bound fits in u32");
        encoded[public_len_offset..public_len_offset + 4].copy_from_slice(&oversized.to_be_bytes());
        assert!(parse(&encoded).is_err());
    }

    #[test]
    fn envelope_rejects_unknown_policy_identifiers() {
        let mut encoded = encode(
            AccessPolicy::None,
            [7; LABEL_HASH_BYTES],
            b"public",
            b"private",
        )
        .expect("encode");
        encoded[MAGIC.len() + 1] = 9;
        assert!(parse(&encoded).is_err());
    }
}

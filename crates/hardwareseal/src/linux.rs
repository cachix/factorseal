use std::io::{Read as _, Write as _};

use zeroize::Zeroizing;

use crate::tpm2::{self, Transport};
use crate::{AccessPolicy, Backend, Error, LABEL_HASH_BYTES};

const MAGIC: &[u8; 8] = b"HSEALTPM";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 1 + LABEL_HASH_BYTES + 4 + 4;
const MAX_BLOB_BYTES: usize = 16 * 1024;
const MAX_TPM_RESPONSE_BYTES: usize = 64 * 1024;

pub(super) fn ensure_available() -> Result<(), Error> {
    tpm2::probe(&mut DeviceTransport::open()?)
}

pub(super) fn seal(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    ensure_supported_policy(policy)?;

    let mut sensitive = Zeroizing::new(Vec::with_capacity(LABEL_HASH_BYTES + secret.len()));
    sensitive.extend_from_slice(&label_hash);
    sensitive.extend_from_slice(secret);
    let object = tpm2::seal(&mut DeviceTransport::open()?, &sensitive)?;

    encode_envelope(policy, label_hash, &object.public, &object.private)
}

pub(super) fn unseal(
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    expected_policy: AccessPolicy,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    ensure_supported_policy(expected_policy)?;
    let parsed = parse_envelope(envelope)?;
    if parsed.policy != expected_policy {
        return Err(Error::InvalidEnvelope(
            "stored access policy does not match the requested policy".to_owned(),
        ));
    }
    if parsed.label_hash != expected_label_hash {
        return Err(Error::InvalidEnvelope(
            "sealed secret belongs to another label".to_owned(),
        ));
    }

    let cleartext = Zeroizing::new(tpm2::unseal(
        &mut DeviceTransport::open()?,
        parsed.public_blob,
        parsed.private_blob,
    )?);
    if cleartext.len() < LABEL_HASH_BYTES || cleartext[..LABEL_HASH_BYTES] != expected_label_hash {
        return Err(Error::InvalidEnvelope(
            "sealed label binding is missing or invalid".to_owned(),
        ));
    }
    Ok(Zeroizing::new(cleartext[LABEL_HASH_BYTES..].to_vec()))
}

struct DeviceTransport(std::fs::File);

impl DeviceTransport {
    fn open() -> Result<Self, Error> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tpmrm0")
            .map(Self)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    Error::NotAvailable
                } else {
                    hardware_error(error)
                }
            })
    }
}

impl Transport for DeviceTransport {
    fn execute(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        self.0.write_all(command).map_err(hardware_error)?;
        let mut response = vec![0; MAX_TPM_RESPONSE_BYTES];
        let length = self.0.read(&mut response).map_err(hardware_error)?;
        response.truncate(length);
        Ok(response)
    }
}

fn ensure_supported_policy(policy: AccessPolicy) -> Result<(), Error> {
    match policy {
        AccessPolicy::None => Ok(()),
        AccessPolicy::Biometric => Err(Error::PolicyNotSupported {
            policy,
            backend: Backend::Tpm,
        }),
    }
}

fn encode_envelope(
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

struct ParsedEnvelope<'a> {
    policy: AccessPolicy,
    label_hash: [u8; LABEL_HASH_BYTES],
    public_blob: &'a [u8],
    private_blob: &'a [u8],
}

fn parse_envelope(input: &[u8]) -> Result<ParsedEnvelope<'_>, Error> {
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
    Ok(ParsedEnvelope {
        policy,
        label_hash,
        public_blob: &input[offset..public_end],
        private_blob: &input[public_end..],
    })
}

fn read_length(input: &[u8], offset: &mut usize) -> Result<usize, Error> {
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

const fn policy_id(policy: AccessPolicy) -> u8 {
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

fn hardware_error(error: impl std::fmt::Display) -> Error {
    Error::Hardware(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_roundtrip() {
        let label_hash = [7; LABEL_HASH_BYTES];
        let encoded =
            encode_envelope(AccessPolicy::None, label_hash, b"public", b"private").expect("encode");
        let parsed = parse_envelope(&encoded).expect("parse");
        assert_eq!(parsed.policy, AccessPolicy::None);
        assert_eq!(parsed.label_hash, label_hash);
        assert_eq!(parsed.public_blob, b"public");
        assert_eq!(parsed.private_blob, b"private");
    }

    #[test]
    fn envelope_rejects_trailing_data() {
        let mut encoded = encode_envelope(
            AccessPolicy::None,
            [7; LABEL_HASH_BYTES],
            b"public",
            b"private",
        )
        .expect("encode");
        encoded.push(0);
        assert!(parse_envelope(&encoded).is_err());
    }

    #[test]
    fn biometric_policy_fails_closed() {
        assert!(matches!(
            ensure_supported_policy(AccessPolicy::Biometric),
            Err(Error::PolicyNotSupported { .. })
        ));
    }
}

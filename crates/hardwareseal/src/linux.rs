use std::io::{Read as _, Write as _};

use zeroize::{Zeroize as _, Zeroizing};

use crate::tpm2::{self, Transport};
use crate::{AccessPolicy, Backend, Error, LABEL_HASH_BYTES, envelope};

pub(super) fn ensure_available() -> Result<(), Error> {
    tpm2::Session::open(DeviceTransport::open()?).map(drop)
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
    let object = tpm2::Session::open(DeviceTransport::open()?)?.seal(&sensitive)?;

    envelope::encode(policy, label_hash, &object.public, &object.private)
}

pub(super) fn unseal(
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    expected_policy: AccessPolicy,
    input: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let total = std::time::Instant::now();
    let result = (|| {
        crate::timing::result("hardware_unseal", "validate_policy", || {
            ensure_supported_policy(expected_policy)
        })?;
        let parsed = crate::timing::result("hardware_unseal", "parse_envelope", || {
            envelope::parse(input)
        })?;
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

        let transport = crate::timing::result("hardware_unseal", "open_tpm_device", || {
            DeviceTransport::open()
        })?;
        let mut session = crate::timing::result("hardware_unseal", "open_tpm_session", || {
            tpm2::Session::open(transport)
        })?;
        let cleartext = crate::timing::result("hardware_unseal", "release_sealed_payload", || {
            session.unseal(parsed.public_blob, parsed.private_blob)
        })?;
        if cleartext.len() < LABEL_HASH_BYTES
            || cleartext[..LABEL_HASH_BYTES] != expected_label_hash
        {
            return Err(Error::InvalidEnvelope(
                "sealed label binding is missing or invalid".to_owned(),
            ));
        }
        Ok(Zeroizing::new(cleartext[LABEL_HASH_BYTES..].to_vec()))
    })();
    crate::timing::record(
        "hardware_unseal",
        "total",
        total,
        if result.is_ok() { "ok" } else { "error" },
    );
    result
}

struct DeviceTransport {
    device: std::fs::File,
    scratch: Zeroizing<Vec<u8>>,
}

impl DeviceTransport {
    fn open() -> Result<Self, Error> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tpmrm0")
            .map(|device| Self {
                device,
                scratch: Zeroizing::new(vec![0; tpm2::MAX_RESPONSE_BYTES]),
            })
            .map_err(|error| match error.kind() {
                // A TPM this process cannot open is as unusable as an absent
                // one. `/dev/tpmrm0` is typically `root:tss 0660`, so a caller
                // outside the `tss` group must reach the same hardware-
                // unavailable fallback as a machine with no TPM at all.
                std::io::ErrorKind::NotFound
                | std::io::ErrorKind::PermissionDenied
                | std::io::ErrorKind::ResourceBusy => Error::NotAvailable,
                _ => hardware_error(error),
            })
    }
}

impl Transport for DeviceTransport {
    fn execute(&mut self, command: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.device.write_all(command).map_err(hardware_error)?;
        let length = self
            .device
            .read(&mut self.scratch)
            .map_err(hardware_error)?;
        // An unseal response lands in `scratch`, so copy out only what the TPM
        // returned and wipe the staging bytes before the next command reuses
        // the buffer.
        let response = Zeroizing::new(self.scratch[..length].to_vec());
        self.scratch[..length].zeroize();
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

fn hardware_error(error: impl std::fmt::Display) -> Error {
    Error::Hardware(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn biometric_policy_fails_closed() {
        assert!(matches!(
            ensure_supported_policy(AccessPolicy::Biometric),
            Err(Error::PolicyNotSupported { .. })
        ));
    }
}

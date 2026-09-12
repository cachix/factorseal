//! macOS 26+ CryptoKit keys whose private material stays in the Secure Enclave.
//!
//! Serialized references are opaque, device-bound capabilities, not private-key
//! exports. Protect them with the application's unlock policy. Unsupported
//! systems and failed native operations never select a software implementation.

use zeroize::Zeroizing;

use crate::{AccessPolicy, Error};

pub mod wrapping;

pub const MLDSA65_PUBLIC_KEY_BYTES: usize = 1952;
pub const MLDSA65_SIGNATURE_BYTES: usize = 3309;
const MAX_REFERENCE_BYTES: usize = 32768;
#[cfg(target_os = "macos")]
const MAX_OUTPUT_BYTES: usize = 65536;
const MAX_INPUT_BYTES: usize = 1024 * 1024;

/// An opaque key reference. It grants use on its originating device subject to
/// its native ACL, so it must not be logged or treated as public metadata.
pub struct MlDsa65Key {
    reference: Zeroizing<Vec<u8>>,
    public_key: Vec<u8>,
}

impl std::fmt::Debug for MlDsa65Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsa65Key").finish_non_exhaustive()
    }
}

/// Whether this OS exposes post-quantum Secure Enclave APIs. Creation remains
/// authoritative: this check does not bypass hardware or authorization errors.
#[must_use]
pub fn is_available() -> bool {
    #[cfg(target_os = "macos")]
    {
        // SAFETY: no arguments, allocations, or ownership cross this C ABI.
        #[allow(unsafe_code)]
        return unsafe { factorseal_apple_pq_available() == 0 };
    }
    #[cfg(not(target_os = "macos"))]
    false
}

impl MlDsa65Key {
    pub fn generate(policy: AccessPolicy) -> Result<Self, Error> {
        let result = call(1, &[], &[], policy)?;
        let (reference, public_key) = split_output(&result, MLDSA65_PUBLIC_KEY_BYTES)?;
        Ok(Self {
            reference: Zeroizing::new(reference.to_vec()),
            public_key: public_key.to_vec(),
        })
    }

    pub fn from_reference(reference: &[u8]) -> Result<Self, Error> {
        validate_reference(reference)?;
        let public_key = call(2, reference, &[], AccessPolicy::None)?;
        if public_key.len() != MLDSA65_PUBLIC_KEY_BYTES {
            return Err(invalid_output());
        }
        Ok(Self {
            reference: Zeroizing::new(reference.to_vec()),
            public_key: public_key.to_vec(),
        })
    }

    #[must_use]
    pub fn reference(&self) -> &[u8] {
        &self.reference
    }

    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Pure ML-DSA-65, empty context; no prehash or proprietary signature framing.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signature = call(3, &self.reference, message, AccessPolicy::None)?;
        if signature.len() != MLDSA65_SIGNATURE_BYTES {
            return Err(invalid_output());
        }
        Ok(signature.to_vec())
    }
}

fn validate_reference(reference: &[u8]) -> Result<(), Error> {
    if reference.is_empty() || reference.len() > MAX_REFERENCE_BYTES {
        return Err(Error::InvalidEnvelope(
            "invalid Secure Enclave key reference length".into(),
        ));
    }
    Ok(())
}

fn split_output(bytes: &[u8], trailing: usize) -> Result<(&[u8], &[u8]), Error> {
    let length = u32::from_be_bytes(
        bytes
            .get(..4)
            .ok_or_else(invalid_output)?
            .try_into()
            .map_err(|_| invalid_output())?,
    ) as usize;
    if length == 0 || length > MAX_REFERENCE_BYTES || bytes.len() != 4 + length + trailing {
        return Err(invalid_output());
    }
    Ok((&bytes[4..4 + length], &bytes[4 + length..]))
}

fn invalid_output() -> Error {
    Error::Hardware("invalid CryptoKit bridge output".into())
}

fn call(
    operation: u32,
    first: &[u8],
    second: &[u8],
    policy: AccessPolicy,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if first.len() > MAX_INPUT_BYTES || second.len() > MAX_INPUT_BYTES {
        return Err(Error::InvalidEnvelope(
            "CryptoKit input exceeds size limit".into(),
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let mut output = Zeroizing::new(vec![0; MAX_OUTPUT_BYTES]);
        let mut length = 0_usize;
        // SAFETY: all slices are live throughout the synchronous call; Swift
        // copies inputs, writes at most capacity bytes, and retains no pointers.
        // usize/Swift Int have the same width on both supported macOS ABIs.
        #[allow(unsafe_code)]
        let status = unsafe {
            factorseal_apple_pq_call(
                operation,
                first.as_ptr(),
                first.len(),
                second.as_ptr(),
                second.len(),
                u32::from(policy == AccessPolicy::Biometric),
                output.as_mut_ptr(),
                output.len(),
                &raw mut length,
            )
        };
        match status {
            0 if length <= output.len() => {
                output.truncate(length);
                Ok(output)
            }
            1 => Err(Error::NotAvailable),
            2 => Err(Error::InvalidEnvelope("invalid CryptoKit input".into())),
            value if value < 0 => Err(super::apple::hardware_error(
                security_framework::base::Error::from_code(value),
            )),
            _ => Err(Error::Hardware(
                "Secure Enclave cryptographic operation failed".into(),
            )),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (operation, policy);
        Err(Error::NotAvailable)
    }
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
unsafe extern "C" {
    fn factorseal_apple_pq_available() -> i32;
    fn factorseal_apple_pq_call(
        operation: u32,
        first: *const u8,
        first_length: usize,
        second: *const u8,
        second_length: usize,
        biometric: u32,
        output: *mut u8,
        capacity: usize,
        output_length: *mut usize,
    ) -> i32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_results_reject_truncation_overflow_and_trailing_bytes() {
        let mut result = vec![0, 0, 0, 1, 42];
        result.extend_from_slice(&[7; MLDSA65_PUBLIC_KEY_BYTES]);
        assert_eq!(
            split_output(&result, MLDSA65_PUBLIC_KEY_BYTES).unwrap().0,
            &[42]
        );
        assert!(split_output(&result[..result.len() - 1], MLDSA65_PUBLIC_KEY_BYTES).is_err());
        result.push(0);
        assert!(split_output(&result, MLDSA65_PUBLIC_KEY_BYTES).is_err());
        for length in [0_u32, u32::MAX, 32769] {
            result[..4].copy_from_slice(&length.to_be_bytes());
            assert!(split_output(&result, MLDSA65_PUBLIC_KEY_BYTES).is_err());
        }
        assert!(validate_reference(&[]).is_err());
        assert!(validate_reference(&vec![0; MAX_REFERENCE_BYTES + 1]).is_err());
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn unsupported_platform_never_generates_software_keys() {
        assert!(!is_available());
        assert!(matches!(
            MlDsa65Key::generate(AccessPolicy::None),
            Err(Error::NotAvailable)
        ));
        assert!(matches!(
            MlDsa65Key::from_reference(&[1]),
            Err(Error::NotAvailable)
        ));
    }
}

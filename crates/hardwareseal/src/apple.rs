use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use security_framework_sys::base::errSecItemNotFound;
use zeroize::Zeroizing;

use crate::{AccessPolicy, Error, LABEL_HASH_BYTES};

const SERVICE: &str = "dev.factorseal.hardwareseal";
const MAGIC: &[u8; 8] = b"HSEALAPL";
const VERSION: u8 = 1;
const ENVELOPE_BYTES: usize = MAGIC.len() + 1 + 1 + LABEL_HASH_BYTES;

pub(super) fn ensure_available(_policy: AccessPolicy) -> Result<(), Error> {
    // Creating the access-control object validates that the Security framework
    // understands the requested policy without creating persistent state.
    access_control(_policy)?;
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec_sec_prime_random())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave);
    SecKey::new(&options).map(drop).map_err(hardware_error)
}

pub(super) fn seal(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    delete_if_present(label_hash, policy)?;
    let mut options = options(label_hash, policy);
    options.set_access_control(access_control(policy)?);
    set_generic_password_options(secret, options).map_err(hardware_error)?;

    let mut envelope = Vec::with_capacity(ENVELOPE_BYTES);
    envelope.extend_from_slice(MAGIC);
    envelope.push(VERSION);
    envelope.push(policy_id(policy));
    envelope.extend_from_slice(&label_hash);
    Ok(envelope)
}

pub(super) fn unseal(
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    expected_policy: AccessPolicy,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    parse_envelope(envelope, expected_label_hash, expected_policy)?;
    generic_password(options(expected_label_hash, expected_policy))
        .map(Zeroizing::new)
        .map_err(hardware_error)
}

pub(super) fn delete(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
) -> Result<(), Error> {
    delete_if_present(label_hash, policy)
}

fn delete_if_present(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
) -> Result<(), Error> {
    match delete_generic_password_options(options(label_hash, policy)) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == errSecItemNotFound => Ok(()),
        Err(error) => Err(hardware_error(error)),
    }
}

fn options(label_hash: [u8; LABEL_HASH_BYTES], policy: AccessPolicy) -> PasswordOptions {
    let account = format!("{}.{}", policy_id(policy), hex_label(label_hash));
    let mut options = PasswordOptions::new_generic_password(SERVICE, &account);
    options.set_access_synchronized(Some(false));
    options.use_protected_keychain();
    options
}

fn access_control(policy: AccessPolicy) -> Result<SecAccessControl, Error> {
    let flags = match policy {
        AccessPolicy::None => AccessControlOptions::empty(),
        AccessPolicy::Biometric => AccessControlOptions::BIOMETRY_CURRENT_SET,
    };
    SecAccessControl::create_with_protection(
        Some(ProtectionMode::AccessibleWhenUnlockedThisDeviceOnly),
        flags.bits(),
    )
    .map_err(hardware_error)
}

fn parse_envelope(
    input: &[u8],
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    expected_policy: AccessPolicy,
) -> Result<(), Error> {
    if input.len() != ENVELOPE_BYTES || &input[..MAGIC.len()] != MAGIC {
        return Err(Error::InvalidEnvelope(
            "missing Apple Keychain envelope header".to_owned(),
        ));
    }
    if input[MAGIC.len()] != VERSION {
        return Err(Error::InvalidEnvelope(format!(
            "unsupported Apple envelope version {}",
            input[MAGIC.len()]
        )));
    }
    if input[MAGIC.len() + 1] != policy_id(expected_policy) {
        return Err(Error::InvalidEnvelope(
            "stored access policy does not match the requested policy".to_owned(),
        ));
    }
    if input[MAGIC.len() + 2..] != expected_label_hash {
        return Err(Error::InvalidEnvelope(
            "sealed secret belongs to another label".to_owned(),
        ));
    }
    Ok(())
}

const fn policy_id(policy: AccessPolicy) -> u8 {
    match policy {
        AccessPolicy::None => 0,
        AccessPolicy::Biometric => 1,
    }
}

fn hex_label(hash: [u8; LABEL_HASH_BYTES]) -> String {
    use std::fmt::Write as _;

    hash.iter()
        .fold(String::with_capacity(hash.len() * 2), |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        })
}

fn hardware_error(error: impl std::fmt::Display) -> Error {
    Error::Hardware(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_binds_label_and_policy() {
        let label = [9; LABEL_HASH_BYTES];
        let mut envelope = Vec::from(MAGIC.as_slice());
        envelope.extend_from_slice(&[VERSION, policy_id(AccessPolicy::None)]);
        envelope.extend_from_slice(&label);
        assert!(parse_envelope(&envelope, label, AccessPolicy::None).is_ok());
        assert!(parse_envelope(&envelope, [8; LABEL_HASH_BYTES], AccessPolicy::None).is_err());
        assert!(parse_envelope(&envelope, label, AccessPolicy::Biometric).is_err());
    }
}

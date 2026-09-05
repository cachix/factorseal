use security_framework::access_control::{ProtectionMode, SecAccessControl};
use security_framework::base::Error as SecurityError;
use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
use security_framework::key::{GenerateKeyOptions, KeyType, SecKey, Token};
use security_framework::passwords::{
    AccessControlOptions, PasswordOptions, delete_generic_password_options, generic_password,
    set_generic_password_options,
};
use security_framework_sys::base::{
    errSecAuthFailed as ERR_SEC_AUTH_FAILED, errSecItemNotFound as ERR_SEC_ITEM_NOT_FOUND,
};
use zeroize::Zeroizing;

use crate::{AccessPolicy, AuthorizationError, Error, LABEL_HASH_BYTES};

const SERVICE: &str = "dev.factorseal.hardwareseal";
const MAGIC: &[u8; 8] = b"HSEALAPL";
const VERSION: u8 = 1;

/// Random per-seal identifier that names the keychain item holding a secret.
///
/// Each `seal` writes a fresh item under its own account, so an envelope names
/// exactly the secret it was created for. That keeps Apple envelopes as
/// self-contained as the TPM and Android ones: re-sealing under a label never
/// silently repoints an older envelope at a newer secret, and it never has to
/// destroy the previous item before writing the new one.
const SEAL_ID_BYTES: usize = 16;
const ENVELOPE_BYTES: usize = MAGIC.len() + 1 + 1 + LABEL_HASH_BYTES + SEAL_ID_BYTES;

// security-framework-sys exposes only a subset of Security.framework status
// constants. These values are stable OSStatus ABI constants from SecBase.h.
const ERR_SEC_USER_CANCELED: i32 = -128;
const ERR_SEC_NOT_AVAILABLE: i32 = -25291;
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
const ERR_SEC_MISSING_ENTITLEMENT: i32 = -34018;

pub(super) fn ensure_available(policy: AccessPolicy) -> Result<(), Error> {
    access_control(policy)?;
    // A Keychain descriptor alone also succeeds on software-only Macs.
    // Probe a transient, non-exportable SEP key, with no persistent location
    // and no biometric ceremony. This key never wraps the vault secret: the
    // payload remains in the device-only Data Protection Keychain.
    let mut options = GenerateKeyOptions::default();
    options
        .set_key_type(KeyType::ec())
        .set_size_in_bits(256)
        .set_token(Token::SecureEnclave);
    SecKey::new(&options)
        .map(drop)
        .map_err(|error| match error.code() {
            ERR_SEC_USER_CANCELED
            | ERR_SEC_AUTH_FAILED
            | ERR_SEC_INTERACTION_NOT_ALLOWED
            | ERR_SEC_MISSING_ENTITLEMENT => hardware_error(error),
            // Unsupported hardware/token, including simulators, fails closed.
            _ => Error::NotAvailable,
        })
}

pub(super) fn seal(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    let mut seal_id = [0_u8; SEAL_ID_BYTES];
    getrandom::fill(&mut seal_id)
        .map_err(|error| Error::Hardware(format!("random generation failed: {error}")))?;

    let mut options = options(&account(label_hash, policy, seal_id));
    options.set_access_control(access_control(policy)?);
    set_generic_password_options(secret, options).map_err(hardware_error)?;

    let mut envelope = Vec::with_capacity(ENVELOPE_BYTES);
    envelope.extend_from_slice(MAGIC);
    envelope.push(VERSION);
    envelope.push(policy_id(policy));
    envelope.extend_from_slice(&label_hash);
    envelope.extend_from_slice(&seal_id);
    Ok(envelope)
}

pub(super) fn unseal(
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    expected_policy: AccessPolicy,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let seal_id = parse_envelope(envelope, expected_label_hash, expected_policy)?;
    generic_password(options(&account(
        expected_label_hash,
        expected_policy,
        seal_id,
    )))
    .map(Zeroizing::new)
    .map_err(hardware_error)
}

pub(super) fn delete(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
) -> Result<(), Error> {
    // Every generation sealed under this label shares one account prefix, so
    // deleting the protector removes the superseded items too.
    let prefix = account_prefix(label_hash, policy);
    for account in stored_accounts(policy)? {
        if account.starts_with(&prefix) {
            delete_if_present(&account)?;
        }
    }
    Ok(())
}

fn delete_if_present(account: &str) -> Result<(), Error> {
    match delete_generic_password_options(options(account)) {
        Ok(()) => Ok(()),
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
        Err(error) => Err(hardware_error(error)),
    }
}

/// List the accounts of every hardwareseal item in the Data Protection Keychain.
fn stored_accounts(policy: AccessPolicy) -> Result<Vec<String>, Error> {
    let mut search = ItemSearchOptions::new();
    search
        .class(ItemClass::generic_password())
        .service(SERVICE)
        .load_attributes(true)
        .limit(Limit::All)
        .ignore_legacy_keychains();
    if policy == AccessPolicy::None {
        // A non-biometric delete must not prompt because another protector uses
        // biometric items under the same service.
        search.skip_authenticated_items(true);
    }
    let results = match search.search() {
        Ok(results) => results,
        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => return Ok(Vec::new()),
        Err(error) => return Err(hardware_error(error)),
    };
    Ok(results
        .iter()
        .filter_map(|result| result.simplify_dict()?.get("acct").cloned())
        .collect())
}

fn options(account: &str) -> PasswordOptions {
    let mut options = PasswordOptions::new_generic_password(SERVICE, account);
    options.set_access_synchronized(Some(false));
    options.use_protected_keychain();
    options
}

fn account_prefix(label_hash: [u8; LABEL_HASH_BYTES], policy: AccessPolicy) -> String {
    format!("{}.{}.", policy_id(policy), hex(&label_hash))
}

fn account(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
    seal_id: [u8; SEAL_ID_BYTES],
) -> String {
    format!("{}{}", account_prefix(label_hash, policy), hex(&seal_id))
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
) -> Result<[u8; SEAL_ID_BYTES], Error> {
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
    let label_start = MAGIC.len() + 2;
    let label_end = label_start + LABEL_HASH_BYTES;
    if input[label_start..label_end] != expected_label_hash {
        return Err(Error::InvalidEnvelope(
            "sealed secret belongs to another label".to_owned(),
        ));
    }
    let seal_id = input[label_end..]
        .try_into()
        .map_err(|_| Error::InvalidEnvelope("truncated Apple seal identifier".to_owned()))?;
    Ok(seal_id)
}

const fn policy_id(policy: AccessPolicy) -> u8 {
    match policy {
        AccessPolicy::None => 0,
        AccessPolicy::Biometric => 1,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    bytes.iter().fold(
        String::with_capacity(bytes.len() * 2),
        |mut output, byte| {
            write!(output, "{byte:02x}").expect("writing to a string cannot fail");
            output
        },
    )
}

fn hardware_error(error: SecurityError) -> Error {
    match error.code() {
        ERR_SEC_USER_CANCELED => Error::Authorization(AuthorizationError::Cancelled),
        ERR_SEC_AUTH_FAILED => Error::Authorization(AuthorizationError::Denied),
        ERR_SEC_INTERACTION_NOT_ALLOWED => Error::Authorization(AuthorizationError::UiUnavailable),
        ERR_SEC_ITEM_NOT_FOUND => Error::Authorization(AuthorizationError::CredentialInvalidated),
        ERR_SEC_NOT_AVAILABLE => Error::NotAvailable,
        ERR_SEC_MISSING_ENTITLEMENT => Error::Hardware(
            "the Apple host application is not signed with a provisioning profile that authorizes its Data Protection Keychain entitlements"
                .to_owned(),
        ),
        _ => Error::Hardware(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(
        label: [u8; LABEL_HASH_BYTES],
        policy: AccessPolicy,
        seal_id: [u8; SEAL_ID_BYTES],
    ) -> Vec<u8> {
        let mut envelope = Vec::from(MAGIC.as_slice());
        envelope.extend_from_slice(&[VERSION, policy_id(policy)]);
        envelope.extend_from_slice(&label);
        envelope.extend_from_slice(&seal_id);
        envelope
    }

    #[test]
    fn envelope_binds_label_and_policy() {
        let label = [9; LABEL_HASH_BYTES];
        let seal_id = [1; SEAL_ID_BYTES];
        let encoded = envelope(label, AccessPolicy::None, seal_id);
        assert_eq!(
            parse_envelope(&encoded, label, AccessPolicy::None).expect("parse"),
            seal_id
        );
        assert!(parse_envelope(&encoded, [8; LABEL_HASH_BYTES], AccessPolicy::None).is_err());
        assert!(parse_envelope(&encoded, label, AccessPolicy::Biometric).is_err());
    }

    #[test]
    fn missing_entitlement_names_the_host_signing_requirement() {
        let error = hardware_error(SecurityError::from_code(ERR_SEC_MISSING_ENTITLEMENT));
        let Error::Hardware(message) = error else {
            panic!("missing entitlement was not classified as a hardware operation failure");
        };
        assert!(message.contains("provisioning profile"));
        assert!(message.contains("Data Protection Keychain"));
    }

    #[test]
    fn envelope_rejects_truncated_and_trailing_data() {
        let label = [9; LABEL_HASH_BYTES];
        let encoded = envelope(label, AccessPolicy::None, [1; SEAL_ID_BYTES]);
        assert!(parse_envelope(&encoded[..encoded.len() - 1], label, AccessPolicy::None).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(parse_envelope(&trailing, label, AccessPolicy::None).is_err());
    }

    #[test]
    fn each_seal_identifier_names_its_own_account() {
        let label = [9; LABEL_HASH_BYTES];
        let first = account(label, AccessPolicy::None, [1; SEAL_ID_BYTES]);
        let second = account(label, AccessPolicy::None, [2; SEAL_ID_BYTES]);
        assert_ne!(first, second);
        let prefix = account_prefix(label, AccessPolicy::None);
        assert!(first.starts_with(&prefix) && second.starts_with(&prefix));
        assert!(!first.starts_with(&account_prefix(label, AccessPolicy::Biometric)));
    }
}

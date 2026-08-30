#![allow(unsafe_code)]

use std::ffi::c_void;

use aes_gcm::aead::{Aead as _, KeyInit as _, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use windows_sys::Win32::Networking::WindowsWebServices::{
    WEBAUTHN_API_VERSION_6, WEBAUTHN_ASSERTION, WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
    WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM, WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS,
    WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6, WEBAUTHN_CLIENT_DATA,
    WEBAUTHN_CLIENT_DATA_CURRENT_VERSION, WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETER, WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
    WEBAUTHN_COSE_CREDENTIAL_PARAMETERS, WEBAUTHN_CREDENTIAL, WEBAUTHN_CREDENTIAL_ATTESTATION,
    WEBAUTHN_CREDENTIAL_CURRENT_VERSION, WEBAUTHN_CREDENTIAL_DETAILS_LIST,
    WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY, WEBAUTHN_CREDENTIALS, WEBAUTHN_GET_CREDENTIALS_OPTIONS,
    WEBAUTHN_GET_CREDENTIALS_OPTIONS_CURRENT_VERSION, WEBAUTHN_HASH_ALGORITHM_SHA_256,
    WEBAUTHN_HMAC_SECRET_SALT, WEBAUTHN_HMAC_SECRET_SALT_VALUES, WEBAUTHN_RP_ENTITY_INFORMATION,
    WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION, WEBAUTHN_USER_ENTITY_INFORMATION,
    WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
    WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED, WebAuthNAuthenticatorGetAssertion,
    WebAuthNAuthenticatorMakeCredential, WebAuthNDeletePlatformCredential, WebAuthNFreeAssertion,
    WebAuthNFreeCredentialAttestation, WebAuthNFreePlatformCredentialList,
    WebAuthNGetApiVersionNumber, WebAuthNGetErrorName, WebAuthNGetPlatformCredentialList,
    WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable,
};
use windows_sys::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_PARAMS2_0, TBS_OWNERAUTH_TYPE_STORAGE_20, TBS_SUCCESS,
    TPM_DEVICE_INFO, TPM_IFTYPE_EMULATOR, TPM_VERSION_20, Tbsi_Context_Create, Tbsi_Get_OwnerAuth,
    Tbsi_GetDeviceInfo, Tbsi_Is_Tpm_Present, Tbsip_Context_Close, Tbsip_Submit_Command,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DestroyWindow, WS_EX_TOOLWINDOW, WS_OVERLAPPED,
};
use zeroize::Zeroizing;

use crate::tpm2::{self, Transport};
use crate::{AccessPolicy, Backend, Error, LABEL_HASH_BYTES};

const MAGIC: &[u8; 8] = b"HSEALTPM";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 1 + LABEL_HASH_BYTES + 4 + 4;
const MAX_BLOB_BYTES: usize = 16 * 1024;
const MAX_TBS_RESPONSE_BYTES: usize = 64 * 1024;
const TBS_E_OWNERAUTH_NOT_FOUND: u32 = 0x8028_4015;

const HELLO_MAGIC: &[u8; 8] = b"HSEALWHL";
const HELLO_VERSION: u8 = 2;
const HELLO_NONCE_BYTES: usize = 12;
const HELLO_PRF_BYTES: usize = 32;
const HELLO_PRF_INPUT_BYTES: usize = 32;
const HELLO_TAG_BYTES: usize = 16;
const HELLO_TIMEOUT_MILLISECONDS: u32 = 120_000;
const HELLO_MAX_CREDENTIAL_ID_BYTES: usize = 4096;
const HELLO_HEADER_BYTES: usize = HELLO_MAGIC.len()
    + 1
    + 1
    + LABEL_HASH_BYTES
    + 4
    + HELLO_PRF_INPUT_BYTES
    + HELLO_NONCE_BYTES
    + 4;
const HELLO_RP_ID_UTF8: &[u8] = b"dev.factorseal.hardwareseal";
const HELLO_RP_ID: windows_sys::core::PCWSTR = windows_sys::core::w!("dev.factorseal.hardwareseal");
const HELLO_RP_NAME: windows_sys::core::PCWSTR = windows_sys::core::w!("Factorseal");
const HELLO_ORIGIN: &str = "https://dev.factorseal.hardwareseal";

pub(super) fn ensure_available(policy: AccessPolicy) -> Result<(), Error> {
    match policy {
        AccessPolicy::None => {
            ensure_hardware_tpm()?;
            tpm2::probe(&mut TbsTransport::open()?)
        }
        AccessPolicy::Biometric => ensure_hello_available(),
    }
}

pub(super) fn seal(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    match policy {
        AccessPolicy::None => tpm_seal_secret(label_hash, secret),
        AccessPolicy::Biometric => hello_seal(label_hash, secret),
    }
}

pub(super) fn unseal(
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    expected_policy: AccessPolicy,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match expected_policy {
        AccessPolicy::None => tpm_unseal_secret(expected_label_hash, envelope),
        AccessPolicy::Biometric => hello_unseal(expected_label_hash, envelope),
    }
}

pub(super) fn delete(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
) -> Result<(), Error> {
    match policy {
        AccessPolicy::None => Ok(()),
        AccessPolicy::Biometric => delete_hello_credentials(label_hash),
    }
}

fn ensure_hello_available() -> Result<(), Error> {
    // Version 6 introduced native PRF inputs and outputs. Refuse older APIs
    // instead of degrading to a separate, bypassable consent prompt.
    if unsafe { WebAuthNGetApiVersionNumber() } < WEBAUTHN_API_VERSION_6 {
        return Err(Error::PolicyNotSupported {
            policy: AccessPolicy::Biometric,
            backend: Backend::WindowsHello,
        });
    }
    let mut available = 0;
    let status =
        unsafe { WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(&raw mut available) };
    check_webauthn(status, "query Windows Hello availability")?;
    if available == 0 {
        return Err(Error::NotAvailable);
    }
    ensure_hardware_tpm()?;
    tpm2::probe(&mut TbsTransport::open()?)
}

fn hello_seal(label_hash: [u8; LABEL_HASH_BYTES], secret: &[u8]) -> Result<Vec<u8>, Error> {
    ensure_hello_available()?;
    let credential_id = create_hello_credential(label_hash)?;
    let result = (|| {
        let tpm_envelope = Zeroizing::new(tpm_seal_secret(label_hash, secret)?);
        let mut prf_input = [0_u8; HELLO_PRF_INPUT_BYTES];
        getrandom::fill(&mut prf_input)
            .map_err(|error| Error::Hardware(format!("random generation failed: {error}")))?;
        let key = evaluate_hello_prf(&credential_id, &prf_input)?;
        let mut nonce = [0_u8; HELLO_NONCE_BYTES];
        getrandom::fill(&mut nonce)
            .map_err(|error| Error::Hardware(format!("random generation failed: {error}")))?;
        let aad = hello_aad(label_hash, &credential_id, prf_input);
        let cipher = Aes256Gcm::new_from_slice(key.as_slice())
            .map_err(|_| Error::Hardware("invalid Windows Hello PRF output".to_owned()))?;
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &tpm_envelope,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Hardware("Windows Hello sealing failed".to_owned()))?;
        encode_hello_envelope(label_hash, &credential_id, prf_input, nonce, &ciphertext)
    })();
    if result.is_err() {
        let _ = delete_hello_credential(&credential_id);
    }
    result
}

fn hello_unseal(
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    ensure_hello_available()?;
    let parsed = parse_hello_envelope(envelope, expected_label_hash)?;
    let key = evaluate_hello_prf(parsed.credential_id, parsed.prf_input)?;
    let aad = hello_aad(expected_label_hash, parsed.credential_id, *parsed.prf_input);
    let cipher = Aes256Gcm::new_from_slice(key.as_slice())
        .map_err(|_| Error::Hardware("invalid Windows Hello PRF output".to_owned()))?;
    let tpm_envelope = cipher
        .decrypt(
            Nonce::from_slice(parsed.nonce),
            Payload {
                msg: parsed.ciphertext,
                aad: &aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| {
            Error::InvalidEnvelope("Windows Hello envelope authentication failed".to_owned())
        })?;
    tpm_unseal_secret(expected_label_hash, &tpm_envelope)
}

fn tpm_seal_secret(label_hash: [u8; LABEL_HASH_BYTES], secret: &[u8]) -> Result<Vec<u8>, Error> {
    ensure_hardware_tpm()?;
    let mut sensitive = Zeroizing::new(Vec::with_capacity(LABEL_HASH_BYTES + secret.len()));
    sensitive.extend_from_slice(&label_hash);
    sensitive.extend_from_slice(secret);
    let object = tpm2::seal(&mut TbsTransport::open()?, &sensitive)?;
    encode_envelope(
        AccessPolicy::None,
        label_hash,
        &object.public,
        &object.private,
    )
}

fn tpm_unseal_secret(
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    ensure_hardware_tpm()?;
    let parsed = parse_envelope(envelope)?;
    if parsed.policy != AccessPolicy::None {
        return Err(Error::InvalidEnvelope(
            "stored TPM access policy is invalid".to_owned(),
        ));
    }
    if parsed.label_hash != expected_label_hash {
        return Err(Error::InvalidEnvelope(
            "sealed secret belongs to another label".to_owned(),
        ));
    }
    let cleartext = Zeroizing::new(tpm2::unseal(
        &mut TbsTransport::open()?,
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

fn create_hello_credential(label_hash: [u8; LABEL_HASH_BYTES]) -> Result<Vec<u8>, Error> {
    let window = WebauthnWindow::create()?;
    let rp = WEBAUTHN_RP_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
        pwszId: HELLO_RP_ID,
        pwszName: HELLO_RP_NAME,
        pwszIcon: std::ptr::null(),
    };
    let mut user_id = label_hash;
    let user_name = wide("factorseal");
    let user_display_name = wide("Factorseal vault key");
    let user = WEBAUTHN_USER_ENTITY_INFORMATION {
        dwVersion: WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
        cbId: u32::try_from(user_id.len())
            .map_err(|_| Error::Hardware("Windows Hello user ID is too large".to_owned()))?,
        pbId: user_id.as_mut_ptr(),
        pwszName: user_name.as_ptr(),
        pwszIcon: std::ptr::null(),
        pwszDisplayName: user_display_name.as_ptr(),
    };
    let mut cose_parameter = WEBAUTHN_COSE_CREDENTIAL_PARAMETER {
        dwVersion: WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
        lAlg: WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256,
    };
    let cose_parameters = WEBAUTHN_COSE_CREDENTIAL_PARAMETERS {
        cCredentialParameters: 1,
        pCredentialParameters: &raw mut cose_parameter,
    };
    let mut client_json = client_data_json("webauthn.create")?;
    let client_data = webauthn_client_data(&mut client_json)?;
    let options = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6,
        dwTimeoutMilliseconds: HELLO_TIMEOUT_MILLISECONDS,
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        dwAttestationConveyancePreference: WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
        bEnablePrf: 1,
        ..WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS::default()
    };
    let mut output = std::ptr::null_mut();
    let status = unsafe {
        WebAuthNAuthenticatorMakeCredential(
            window.hwnd(),
            &raw const rp,
            &raw const user,
            &raw const cose_parameters,
            &raw const client_data,
            &raw const options,
            &raw mut output,
        )
    };
    check_webauthn(status, "create Windows Hello credential")?;
    let output = AttestationGuard::new(output)?;
    let attestation = output.get();
    let credential_id = copy_output(
        attestation.pbCredentialId,
        attestation.cbCredentialId,
        HELLO_MAX_CREDENTIAL_ID_BYTES,
        "Windows Hello credential ID",
    )?;
    if attestation.bPrfEnabled == 0 {
        let _ = delete_hello_credential(&credential_id);
        return Err(Error::PolicyNotSupported {
            policy: AccessPolicy::Biometric,
            backend: Backend::WindowsHello,
        });
    }
    Ok(credential_id)
}

fn evaluate_hello_prf(
    credential_id: &[u8],
    prf_input: &[u8; HELLO_PRF_INPUT_BYTES],
) -> Result<Zeroizing<[u8; HELLO_PRF_BYTES]>, Error> {
    let window = WebauthnWindow::create()?;
    let mut credential_id = credential_id.to_vec();
    let mut credential = WEBAUTHN_CREDENTIAL {
        dwVersion: WEBAUTHN_CREDENTIAL_CURRENT_VERSION,
        cbId: u32::try_from(credential_id.len())
            .map_err(|_| Error::InvalidEnvelope("credential ID is too large".to_owned()))?,
        pbId: credential_id.as_mut_ptr(),
        pwszCredentialType: WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
    };
    let credentials = WEBAUTHN_CREDENTIALS {
        cCredentials: 1,
        pCredentials: &raw mut credential,
    };
    let mut salt_bytes = *prf_input;
    let mut salt = WEBAUTHN_HMAC_SECRET_SALT {
        cbFirst: u32::try_from(HELLO_PRF_BYTES).expect("PRF length fits in u32"),
        pbFirst: salt_bytes.as_mut_ptr(),
        cbSecond: 0,
        pbSecond: std::ptr::null_mut(),
    };
    let mut salt_values = WEBAUTHN_HMAC_SECRET_SALT_VALUES {
        pGlobalHmacSalt: &raw mut salt,
        cCredWithHmacSecretSaltList: 0,
        pCredWithHmacSecretSaltList: std::ptr::null_mut(),
    };
    let mut client_json = client_data_json("webauthn.get")?;
    let client_data = webauthn_client_data(&mut client_json)?;
    let options = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS {
        dwVersion: WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6,
        dwTimeoutMilliseconds: HELLO_TIMEOUT_MILLISECONDS,
        CredentialList: credentials,
        dwAuthenticatorAttachment: WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM,
        dwUserVerificationRequirement: WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED,
        pHmacSecretSaltValues: &raw mut salt_values,
        ..WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS::default()
    };
    let mut output = std::ptr::null_mut();
    let status = unsafe {
        WebAuthNAuthenticatorGetAssertion(
            window.hwnd(),
            HELLO_RP_ID,
            &raw const client_data,
            &raw const options,
            &raw mut output,
        )
    };
    check_webauthn(status, "evaluate Windows Hello PRF")?;
    let output = AssertionGuard::new(output)?;
    let assertion = output.get();
    let returned_id = unsafe {
        checked_output_slice(
            assertion.Credential.pbId,
            assertion.Credential.cbId,
            HELLO_MAX_CREDENTIAL_ID_BYTES,
            "returned Windows Hello credential ID",
        )?
    };
    if returned_id != credential_id {
        return Err(Error::InvalidEnvelope(
            "Windows Hello returned another credential".to_owned(),
        ));
    }
    let authenticator_data = unsafe {
        checked_output_slice(
            assertion.pbAuthenticatorData,
            assertion.cbAuthenticatorData,
            MAX_BLOB_BYTES,
            "Windows Hello authenticator data",
        )?
    };
    validate_authenticator_data(authenticator_data)?;
    if assertion.pHmacSecret.is_null() {
        return Err(Error::PolicyNotSupported {
            policy: AccessPolicy::Biometric,
            backend: Backend::WindowsHello,
        });
    }
    let output_salt = unsafe { &*assertion.pHmacSecret };
    let output_bytes = unsafe {
        checked_output_slice(
            output_salt.pbFirst,
            output_salt.cbFirst,
            HELLO_PRF_BYTES,
            "Windows Hello PRF output",
        )?
    };
    if output_bytes.len() != HELLO_PRF_BYTES {
        return Err(Error::Hardware(
            "Windows Hello returned an invalid PRF output length".to_owned(),
        ));
    }
    let mut key = Zeroizing::new([0_u8; HELLO_PRF_BYTES]);
    key.copy_from_slice(output_bytes);
    Ok(key)
}

fn delete_hello_credentials(label_hash: [u8; LABEL_HASH_BYTES]) -> Result<(), Error> {
    ensure_hello_available()?;
    let options = WEBAUTHN_GET_CREDENTIALS_OPTIONS {
        dwVersion: WEBAUTHN_GET_CREDENTIALS_OPTIONS_CURRENT_VERSION,
        pwszRpId: HELLO_RP_ID,
        bBrowserInPrivateMode: 0,
    };
    let mut output = std::ptr::null_mut();
    let status = unsafe { WebAuthNGetPlatformCredentialList(&raw const options, &raw mut output) };
    check_webauthn(status, "list Windows Hello credentials")?;
    let output = CredentialListGuard::new(output)?;
    let list = output.get();
    if list.cCredentialDetails > 4096 {
        return Err(Error::Hardware(
            "Windows Hello returned too many credentials".to_owned(),
        ));
    }
    let details = unsafe {
        checked_pointer_slice(
            list.ppCredentialDetails,
            list.cCredentialDetails,
            "Windows Hello credential list",
        )?
    };
    let mut matching_ids = Vec::new();
    for detail in details {
        if detail.is_null() {
            return Err(Error::Hardware(
                "Windows Hello returned a null credential detail".to_owned(),
            ));
        }
        let detail = unsafe { &**detail };
        if detail.pUserInformation.is_null() {
            continue;
        }
        let user = unsafe { &*detail.pUserInformation };
        let user_id = unsafe {
            checked_output_slice(user.pbId, user.cbId, 64, "Windows Hello credential user ID")?
        };
        if user_id == label_hash {
            matching_ids.push(copy_output(
                detail.pbCredentialID,
                detail.cbCredentialID,
                HELLO_MAX_CREDENTIAL_ID_BYTES,
                "Windows Hello credential ID",
            )?);
        }
    }
    drop(output);
    for credential_id in matching_ids {
        delete_hello_credential(&credential_id)?;
    }
    Ok(())
}

fn delete_hello_credential(credential_id: &[u8]) -> Result<(), Error> {
    let length = u32::try_from(credential_id.len())
        .map_err(|_| Error::InvalidEnvelope("credential ID is too large".to_owned()))?;
    let status = unsafe { WebAuthNDeletePlatformCredential(length, credential_id.as_ptr()) };
    check_webauthn(status, "delete Windows Hello credential")
}

fn client_data_json(operation_type: &str) -> Result<Vec<u8>, Error> {
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge)
        .map_err(|error| Error::Hardware(format!("random generation failed: {error}")))?;
    Ok(format!(
        "{{\"type\":\"{operation_type}\",\"challenge\":\"{}\",\"origin\":\"{HELLO_ORIGIN}\"}}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes())
}

fn webauthn_client_data(json: &mut [u8]) -> Result<WEBAUTHN_CLIENT_DATA, Error> {
    Ok(WEBAUTHN_CLIENT_DATA {
        dwVersion: WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
        cbClientDataJSON: u32::try_from(json.len())
            .map_err(|_| Error::Hardware("WebAuthn client data is too large".to_owned()))?,
        pbClientDataJSON: json.as_mut_ptr(),
        pwszHashAlgId: WEBAUTHN_HASH_ALGORITHM_SHA_256,
    })
}

fn validate_authenticator_data(authenticator_data: &[u8]) -> Result<(), Error> {
    // Authenticator data is rpIdHash (32), flags (1), signCount (4), followed
    // by optional attested-credential or extension data.
    if authenticator_data.len() < 37 {
        return Err(Error::Hardware(
            "Windows Hello returned truncated authenticator data".to_owned(),
        ));
    }
    let expected_rp_hash: [u8; 32] = Sha256::digest(HELLO_RP_ID_UTF8).into();
    if authenticator_data[..32] != expected_rp_hash {
        return Err(Error::Hardware(
            "Windows Hello assertion is bound to another relying party".to_owned(),
        ));
    }
    let flags = authenticator_data[32];
    if flags & 0x01 == 0 {
        return Err(Error::Hardware(
            "Windows Hello assertion did not confirm user presence".to_owned(),
        ));
    }
    if flags & 0x04 == 0 {
        return Err(Error::Hardware(
            "Windows Hello assertion did not verify the user".to_owned(),
        ));
    }
    Ok(())
}

fn hello_aad(
    label_hash: [u8; LABEL_HASH_BYTES],
    credential_id: &[u8],
    prf_input: [u8; HELLO_PRF_INPUT_BYTES],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        HELLO_MAGIC.len() + 2 + LABEL_HASH_BYTES + credential_id.len() + HELLO_PRF_INPUT_BYTES,
    );
    aad.extend_from_slice(HELLO_MAGIC);
    aad.push(HELLO_VERSION);
    aad.push(policy_id(AccessPolicy::Biometric));
    aad.extend_from_slice(&label_hash);
    aad.extend_from_slice(credential_id);
    aad.extend_from_slice(&prf_input);
    aad
}

fn encode_hello_envelope(
    label_hash: [u8; LABEL_HASH_BYTES],
    credential_id: &[u8],
    prf_input: [u8; HELLO_PRF_INPUT_BYTES],
    nonce: [u8; HELLO_NONCE_BYTES],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if credential_id.is_empty() || credential_id.len() > HELLO_MAX_CREDENTIAL_ID_BYTES {
        return Err(Error::Hardware(
            "Windows Hello returned an invalid credential ID length".to_owned(),
        ));
    }
    if ciphertext.len() < HELLO_TAG_BYTES || ciphertext.len() > MAX_BLOB_BYTES {
        return Err(Error::Hardware(
            "Windows Hello returned an invalid ciphertext length".to_owned(),
        ));
    }
    let credential_len = u32::try_from(credential_id.len())
        .map_err(|_| Error::Hardware("Windows Hello credential ID is too large".to_owned()))?;
    let ciphertext_len = u32::try_from(ciphertext.len())
        .map_err(|_| Error::Hardware("Windows Hello ciphertext is too large".to_owned()))?;
    let mut output =
        Vec::with_capacity(HELLO_HEADER_BYTES + credential_id.len() + ciphertext.len());
    output.extend_from_slice(HELLO_MAGIC);
    output.push(HELLO_VERSION);
    output.push(policy_id(AccessPolicy::Biometric));
    output.extend_from_slice(&label_hash);
    output.extend_from_slice(&credential_len.to_be_bytes());
    output.extend_from_slice(&prf_input);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext_len.to_be_bytes());
    output.extend_from_slice(credential_id);
    output.extend_from_slice(ciphertext);
    Ok(output)
}

struct ParsedHelloEnvelope<'a> {
    credential_id: &'a [u8],
    prf_input: &'a [u8; HELLO_PRF_INPUT_BYTES],
    nonce: &'a [u8; HELLO_NONCE_BYTES],
    ciphertext: &'a [u8],
}

fn parse_hello_envelope(
    input: &[u8],
    expected_label_hash: [u8; LABEL_HASH_BYTES],
) -> Result<ParsedHelloEnvelope<'_>, Error> {
    if input.len() < HELLO_HEADER_BYTES || &input[..HELLO_MAGIC.len()] != HELLO_MAGIC {
        return Err(Error::InvalidEnvelope(
            "missing Windows Hello envelope header".to_owned(),
        ));
    }
    if input[HELLO_MAGIC.len()] != HELLO_VERSION {
        return Err(Error::InvalidEnvelope(format!(
            "unsupported Windows Hello envelope version {}",
            input[HELLO_MAGIC.len()]
        )));
    }
    if input[HELLO_MAGIC.len() + 1] != policy_id(AccessPolicy::Biometric) {
        return Err(Error::InvalidEnvelope(
            "stored access policy is not Windows Hello biometric".to_owned(),
        ));
    }
    let mut offset = HELLO_MAGIC.len() + 2;
    if input[offset..offset + LABEL_HASH_BYTES] != expected_label_hash {
        return Err(Error::InvalidEnvelope(
            "sealed secret belongs to another label".to_owned(),
        ));
    }
    offset += LABEL_HASH_BYTES;
    let credential_len = read_length(input, &mut offset)?;
    if credential_len == 0 || credential_len > HELLO_MAX_CREDENTIAL_ID_BYTES {
        return Err(Error::InvalidEnvelope(
            "Windows Hello credential ID has an invalid length".to_owned(),
        ));
    }
    let prf_input_end = offset
        .checked_add(HELLO_PRF_INPUT_BYTES)
        .ok_or_else(|| Error::InvalidEnvelope("envelope length overflow".to_owned()))?;
    let prf_input: &[u8; HELLO_PRF_INPUT_BYTES] = input
        .get(offset..prf_input_end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::InvalidEnvelope("truncated Windows Hello PRF input".to_owned()))?;
    offset = prf_input_end;
    let nonce_end = offset
        .checked_add(HELLO_NONCE_BYTES)
        .ok_or_else(|| Error::InvalidEnvelope("envelope length overflow".to_owned()))?;
    let nonce: &[u8; HELLO_NONCE_BYTES] = input
        .get(offset..nonce_end)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::InvalidEnvelope("truncated Windows Hello nonce".to_owned()))?;
    offset = nonce_end;
    let ciphertext_len = read_length(input, &mut offset)?;
    if !(HELLO_TAG_BYTES..=MAX_BLOB_BYTES).contains(&ciphertext_len) {
        return Err(Error::InvalidEnvelope(
            "Windows Hello ciphertext has an invalid length".to_owned(),
        ));
    }
    let credential_end = offset
        .checked_add(credential_len)
        .ok_or_else(|| Error::InvalidEnvelope("envelope length overflow".to_owned()))?;
    let expected = credential_end
        .checked_add(ciphertext_len)
        .ok_or_else(|| Error::InvalidEnvelope("envelope length overflow".to_owned()))?;
    if expected != input.len() {
        return Err(Error::InvalidEnvelope(
            "Windows Hello envelope lengths do not match its contents".to_owned(),
        ));
    }
    Ok(ParsedHelloEnvelope {
        credential_id: &input[offset..credential_end],
        prf_input,
        nonce,
        ciphertext: &input[credential_end..],
    })
}

fn check_webauthn(status: i32, operation: &str) -> Result<(), Error> {
    if status >= 0 {
        return Ok(());
    }
    let name = unsafe { webauthn_error_name(status) };
    Err(Error::Hardware(format!(
        "failed to {operation}: {name} (0x{:08x})",
        status.cast_unsigned()
    )))
}

unsafe fn webauthn_error_name(status: i32) -> String {
    let pointer = unsafe { WebAuthNGetErrorName(status) };
    if pointer.is_null() {
        return "unknown WebAuthn error".to_owned();
    }
    let mut length = 0;
    while length < 256 && unsafe { *pointer.add(length) } != 0 {
        length += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(pointer, length) })
}

fn copy_output(
    pointer: *const u8,
    length: u32,
    maximum: usize,
    description: &str,
) -> Result<Vec<u8>, Error> {
    unsafe { checked_output_slice(pointer, length, maximum, description).map(ToOwned::to_owned) }
}

unsafe fn checked_output_slice<'a>(
    pointer: *const u8,
    length: u32,
    maximum: usize,
    description: &str,
) -> Result<&'a [u8], Error> {
    let length = usize::try_from(length)
        .map_err(|_| Error::Hardware(format!("{description} length overflow")))?;
    if length > maximum || (length != 0 && pointer.is_null()) {
        return Err(Error::Hardware(format!(
            "{description} has an invalid length or pointer"
        )));
    }
    let pointer = if length == 0 {
        std::ptr::NonNull::<u8>::dangling().as_ptr()
    } else {
        pointer
    };
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

unsafe fn checked_pointer_slice<'a, T>(
    pointer: *const T,
    length: u32,
    description: &str,
) -> Result<&'a [T], Error> {
    let length = usize::try_from(length)
        .map_err(|_| Error::Hardware(format!("{description} length overflow")))?;
    if length != 0 && pointer.is_null() {
        return Err(Error::Hardware(format!("{description} has a null pointer")));
    }
    let pointer = if length == 0 {
        std::ptr::NonNull::<T>::dangling().as_ptr()
    } else {
        pointer
    };
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

struct WebauthnWindow(windows_sys::Win32::Foundation::HWND);

impl WebauthnWindow {
    fn create() -> Result<Self, Error> {
        // Use the system STATIC class to avoid global class registration. The
        // hidden tool window belongs to this process and exists only while the
        // synchronous Windows Hello ceremony is active. Never attach the
        // security prompt to another process's foreground or desktop window.
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_TOOLWINDOW,
                windows_sys::core::w!("STATIC"),
                windows_sys::core::w!("Factorseal authentication"),
                WS_OVERLAPPED,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if hwnd.is_null() {
            Err(Error::Hardware(
                "failed to create the Windows Hello owner window".to_owned(),
            ))
        } else {
            Ok(Self(hwnd))
        }
    }

    const fn hwnd(&self) -> windows_sys::Win32::Foundation::HWND {
        self.0
    }
}

impl Drop for WebauthnWindow {
    fn drop(&mut self) {
        let _ = unsafe { DestroyWindow(self.0) };
    }
}

struct AttestationGuard(*mut WEBAUTHN_CREDENTIAL_ATTESTATION);

impl AttestationGuard {
    fn new(pointer: *mut WEBAUTHN_CREDENTIAL_ATTESTATION) -> Result<Self, Error> {
        if pointer.is_null() {
            Err(Error::Hardware(
                "Windows Hello returned a null credential attestation".to_owned(),
            ))
        } else {
            Ok(Self(pointer))
        }
    }

    fn get(&self) -> &WEBAUTHN_CREDENTIAL_ATTESTATION {
        unsafe { &*self.0 }
    }
}

impl Drop for AttestationGuard {
    fn drop(&mut self) {
        unsafe { WebAuthNFreeCredentialAttestation(self.0) };
    }
}

struct AssertionGuard(*mut WEBAUTHN_ASSERTION);

impl AssertionGuard {
    fn new(pointer: *mut WEBAUTHN_ASSERTION) -> Result<Self, Error> {
        if pointer.is_null() {
            Err(Error::Hardware(
                "Windows Hello returned a null assertion".to_owned(),
            ))
        } else {
            Ok(Self(pointer))
        }
    }

    fn get(&self) -> &WEBAUTHN_ASSERTION {
        unsafe { &*self.0 }
    }
}

impl Drop for AssertionGuard {
    fn drop(&mut self) {
        unsafe { WebAuthNFreeAssertion(self.0) };
    }
}

struct CredentialListGuard(*mut WEBAUTHN_CREDENTIAL_DETAILS_LIST);

impl CredentialListGuard {
    fn new(pointer: *mut WEBAUTHN_CREDENTIAL_DETAILS_LIST) -> Result<Self, Error> {
        if pointer.is_null() {
            Err(Error::Hardware(
                "Windows Hello returned a null credential list".to_owned(),
            ))
        } else {
            Ok(Self(pointer))
        }
    }

    fn get(&self) -> &WEBAUTHN_CREDENTIAL_DETAILS_LIST {
        unsafe { &*self.0 }
    }
}

impl Drop for CredentialListGuard {
    fn drop(&mut self) {
        unsafe { WebAuthNFreePlatformCredentialList(self.0) };
    }
}

fn ensure_hardware_tpm() -> Result<(), Error> {
    // SAFETY: This function has no pointer arguments and only queries TBS state.
    if unsafe { Tbsi_Is_Tpm_Present() } == 0 {
        return Err(Error::NotAvailable);
    }
    let mut info = TPM_DEVICE_INFO {
        structVersion: 1,
        ..TPM_DEVICE_INFO::default()
    };
    let size = u32::try_from(std::mem::size_of::<TPM_DEVICE_INFO>())
        .map_err(|_| Error::Hardware("TPM device information size overflow".to_owned()))?;
    // SAFETY: `info` is writable for exactly `size` bytes and lives for the call.
    let status = unsafe { Tbsi_GetDeviceInfo(size, (&raw mut info).cast::<c_void>()) };
    if status != TBS_SUCCESS {
        return Err(tbs_error("query TPM device information", status));
    }
    if info.tpmVersion != TPM_VERSION_20 || info.tpmInterfaceType == TPM_IFTYPE_EMULATOR {
        return Err(Error::NotAvailable);
    }
    Ok(())
}

struct TbsTransport(*mut c_void);

impl TbsTransport {
    fn open() -> Result<Self, Error> {
        let params = TBS_CONTEXT_PARAMS2 {
            version: TPM_VERSION_20,
            Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 1 << 2 },
        };
        let mut handle = std::ptr::null_mut();
        // SAFETY: `params` has the documented v2 layout, and `handle` is a
        // valid writable output pointer. TBS retains neither pointer.
        let status = unsafe {
            Tbsi_Context_Create(
                (&raw const params).cast::<TBS_CONTEXT_PARAMS>(),
                &raw mut handle,
            )
        };
        if status != TBS_SUCCESS {
            return Err(tbs_error("open TPM 2.0 context", status));
        }
        Ok(Self(handle))
    }
}

impl Transport for TbsTransport {
    fn execute(&mut self, command: &[u8]) -> Result<Vec<u8>, Error> {
        let command_len = u32::try_from(command.len())
            .map_err(|_| Error::Hardware("TPM command is too large".to_owned()))?;
        let mut response = vec![0; MAX_TBS_RESPONSE_BYTES];
        let mut response_len = u32::try_from(response.len())
            .map_err(|_| Error::Hardware("TPM response buffer is too large".to_owned()))?;
        // SAFETY: Both buffers are valid for their declared lengths. The
        // context is owned by this value and remains open during the call.
        let status = unsafe {
            Tbsip_Submit_Command(
                self.0,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                command.as_ptr(),
                command_len,
                response.as_mut_ptr(),
                &raw mut response_len,
            )
        };
        if status != TBS_SUCCESS {
            return Err(tbs_error("submit TPM command", status));
        }
        response.truncate(response_len as usize);
        Ok(response)
    }

    fn owner_auth(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let mut auth = Zeroizing::new(vec![0; 64]);
        let mut length = u32::try_from(auth.len()).map_err(|_| {
            Error::Hardware("TPM owner authorization buffer is too large".to_owned())
        })?;
        // SAFETY: `auth` is writable for `length` bytes, and the context remains
        // valid for the duration of the call.
        let status = unsafe {
            Tbsi_Get_OwnerAuth(
                self.0,
                TBS_OWNERAUTH_TYPE_STORAGE_20,
                auth.as_mut_ptr(),
                &raw mut length,
            )
        };
        if status == TBS_E_OWNERAUTH_NOT_FOUND {
            return Ok(Zeroizing::new(Vec::new()));
        }
        if status != TBS_SUCCESS {
            return Err(tbs_error(
                "retrieve TPM storage hierarchy authorization",
                status,
            ));
        }
        auth.truncate(length as usize);
        Ok(auth)
    }
}

impl Drop for TbsTransport {
    fn drop(&mut self) {
        // SAFETY: The handle came from `Tbsi_Context_Create`, is owned by this
        // value, and is closed exactly once here.
        let _ = unsafe { Tbsip_Context_Close(self.0) };
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

fn tbs_error(operation: &str, status: u32) -> Error {
    Error::Hardware(format!("failed to {operation}: TBS status 0x{status:08x}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_envelope_binds_label_and_lengths() {
        let label = [7; LABEL_HASH_BYTES];
        let credential = [3; 64];
        let prf_input = [4; HELLO_PRF_INPUT_BYTES];
        let nonce = [5; HELLO_NONCE_BYTES];
        let ciphertext = [9; HELLO_TAG_BYTES + 12];
        let envelope = encode_hello_envelope(label, &credential, prf_input, nonce, &ciphertext)
            .expect("encode");
        let parsed = parse_hello_envelope(&envelope, label).expect("parse");
        assert_eq!(parsed.credential_id, credential);
        assert_eq!(parsed.prf_input, &prf_input);
        assert_eq!(parsed.nonce, &nonce);
        assert_eq!(parsed.ciphertext, ciphertext);
        assert!(parse_hello_envelope(&envelope, [8; LABEL_HASH_BYTES]).is_err());

        let mut trailing = envelope;
        trailing.push(0);
        assert!(parse_hello_envelope(&trailing, label).is_err());
    }

    #[test]
    fn hello_aad_binds_credential_and_prf_input() {
        assert_ne!(
            hello_aad([1; LABEL_HASH_BYTES], b"credential-a", [2; 32]),
            hello_aad([1; LABEL_HASH_BYTES], b"credential-b", [2; 32])
        );
        assert_ne!(
            hello_aad([1; LABEL_HASH_BYTES], b"credential", [2; 32]),
            hello_aad([1; LABEL_HASH_BYTES], b"credential", [3; 32])
        );
    }

    #[test]
    fn authenticator_data_requires_rp_presence_and_verification() {
        let mut data = [0_u8; 37];
        data[..32].copy_from_slice(&Sha256::digest(HELLO_RP_ID_UTF8));
        data[32] = 0x01 | 0x04;
        validate_authenticator_data(&data).expect("valid authenticator data");

        let mut wrong_rp = data;
        wrong_rp[0] ^= 1;
        assert!(validate_authenticator_data(&wrong_rp).is_err());
        data[32] = 0x04;
        assert!(validate_authenticator_data(&data).is_err());
        data[32] = 0x01;
        assert!(validate_authenticator_data(&data).is_err());
        assert!(validate_authenticator_data(&data[..36]).is_err());
    }
}

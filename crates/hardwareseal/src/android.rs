#![allow(unsafe_code)]

use jni::objects::{JByteArray, JClass, JObject, JObjectArray, JString, JThrowable, JValue};
use jni::{JNIEnv, JavaVM};
use zeroize::Zeroizing;

use crate::{AccessPolicy, AuthorizationError, Backend, Error, LABEL_HASH_BYTES};

const MAGIC: &[u8; 8] = b"HSEALAND";
const VERSION: u8 = 1;
const HEADER_BYTES: usize = MAGIC.len() + 1 + 1 + LABEL_HASH_BYTES + 1 + 4;
const MAX_IV_BYTES: usize = 32;
const MAX_CIPHERTEXT_BYTES: usize = 256;
const PURPOSE_ENCRYPT_DECRYPT: i32 = 3;
const ENCRYPT_MODE: i32 = 1;
const DECRYPT_MODE: i32 = 2;

pub(super) fn open(label_hash: [u8; LABEL_HASH_BYTES], policy: AccessPolicy) -> Result<(), Error> {
    if policy == AccessPolicy::Biometric {
        return Err(Error::PolicyNotSupported {
            policy,
            backend: Backend::AndroidKeystore,
        });
    }
    with_env(|env| {
        let sdk = sdk_version(env)?;
        if sdk < 23 {
            return Err(Error::NotAvailable);
        }
        let store = key_store(env)?;
        let alias = alias(label_hash, policy);
        let key = get_or_create_key(env, &store, &alias)?;
        if let Err(error) = ensure_hardware_key(env, &key) {
            // `delete_alias` is itself a JNI call, and calling into JNI with a
            // pending exception aborts the process under CheckJNI. Take the
            // exception first, then clean up the rejected alias.
            let error = take_pending_exception(env).unwrap_or(error);
            let _ = delete_alias(env, &store, &alias);
            return Err(error);
        }
        Ok(())
    })
}

pub(super) fn seal(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
    secret: &[u8],
) -> Result<Vec<u8>, Error> {
    with_env(|env| {
        let alias = alias(label_hash, policy);
        let key_store = key_store(env)?;
        let key = get_or_create_key(env, &key_store, &alias)?;
        ensure_hardware_key(env, &key)?;

        let cipher = cipher(env)?;
        call_method(
            env,
            &cipher,
            "init",
            "(ILjava/security/Key;)V",
            &[JValue::Int(ENCRYPT_MODE), JValue::Object(&key)],
        )?;
        update_aad(env, &cipher, label_hash, policy)?;
        let plaintext = env.byte_array_from_slice(secret).map_err(jni_error)?;
        let plaintext_object = JObject::from(plaintext);
        let ciphertext = call_method(
            env,
            &cipher,
            "doFinal",
            "([B)[B",
            &[JValue::Object(&plaintext_object)],
        )?
        .l()
        .map_err(jni_error)?;
        let ciphertext = JByteArray::from(ciphertext);
        let ciphertext = env.convert_byte_array(ciphertext).map_err(jni_error)?;

        let iv = env
            .call_method(&cipher, "getIV", "()[B", &[])
            .map_err(jni_error)?
            .l()
            .map_err(jni_error)?;
        let iv = env
            .convert_byte_array(JByteArray::from(iv))
            .map_err(jni_error)?;
        encode_envelope(policy, label_hash, &iv, &ciphertext)
    })
}

pub(super) fn unseal(
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    expected_policy: AccessPolicy,
    envelope: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let parsed = parse_envelope(envelope, expected_label_hash, expected_policy)?;
    with_env(|env| {
        let key_store = key_store(env)?;
        let key = get_existing_key(
            env,
            &key_store,
            &alias(expected_label_hash, expected_policy),
        )?;
        ensure_hardware_key(env, &key)?;

        let cipher = cipher(env)?;
        let iv = env.byte_array_from_slice(parsed.iv).map_err(jni_error)?;
        let iv_object = JObject::from(iv);
        let params = env
            .new_object(
                "javax/crypto/spec/GCMParameterSpec",
                "(I[B)V",
                &[JValue::Int(128), JValue::Object(&iv_object)],
            )
            .map_err(jni_error)?;
        call_method(
            env,
            &cipher,
            "init",
            "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[
                JValue::Int(DECRYPT_MODE),
                JValue::Object(&key),
                JValue::Object(&params),
            ],
        )?;
        update_aad(env, &cipher, expected_label_hash, expected_policy)?;
        let ciphertext = env
            .byte_array_from_slice(parsed.ciphertext)
            .map_err(jni_error)?;
        let ciphertext_object = JObject::from(ciphertext);
        let plaintext = call_method(
            env,
            &cipher,
            "doFinal",
            "([B)[B",
            &[JValue::Object(&ciphertext_object)],
        )?
        .l()
        .map_err(jni_error)?;
        env.convert_byte_array(JByteArray::from(plaintext))
            .map(Zeroizing::new)
            .map_err(jni_error)
    })
}

pub(super) fn delete(
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
) -> Result<(), Error> {
    with_env(|env| {
        let key_store = key_store(env)?;
        delete_alias(env, &key_store, &alias(label_hash, policy))
    })
}

fn delete_alias(env: &mut JNIEnv<'_>, key_store: &JObject<'_>, alias: &str) -> Result<(), Error> {
    let alias = env.new_string(alias).map_err(jni_error)?;
    let alias_object = JObject::from(alias);
    env.call_method(
        key_store,
        "deleteEntry",
        "(Ljava/lang/String;)V",
        &[JValue::Object(&alias_object)],
    )
    .map(drop)
    .map_err(jni_error)
}

fn with_env<T>(operation: impl FnOnce(&mut JNIEnv<'_>) -> Result<T, Error>) -> Result<T, Error> {
    let context =
        std::panic::catch_unwind(ndk_context::android_context).map_err(|_| Error::NotAvailable)?;
    // SAFETY: ndk-context is initialized by the Android runtime and owns a
    // process-lifetime JavaVM pointer. JavaVM does not destroy it on drop.
    let vm = unsafe { JavaVM::from_raw(context.vm().cast()) }.map_err(jni_error)?;
    let mut env = vm.attach_current_thread().map_err(jni_error)?;
    let result = operation(&mut env);
    let pending = take_pending_exception(&mut env);
    match (result, pending) {
        // jni-rs reports every Java throw as the same opaque `JavaException`,
        // so the pending throwable is the only place the actual outcome is
        // recorded. Refine the untyped error with it, but never override an
        // outcome a caller already classified.
        (Err(Error::Hardware(_)), Some(error)) => Err(error),
        (result, _) => result,
    }
}

/// Clear the pending Java exception, if any, and classify it.
///
/// Clearing is mandatory before any further JNI call on this thread; the
/// classification is what lets callers tell "credential invalidated, start
/// recovery" from "transient device failure, retry".
fn take_pending_exception(env: &mut JNIEnv<'_>) -> Option<Error> {
    if !env.exception_check().unwrap_or(false) {
        return None;
    }
    let throwable = env.exception_occurred().ok();
    let _ = env.exception_clear();
    let class = throwable.and_then(|throwable| exception_class_name(env, &throwable))?;
    Some(classify_exception(&class))
}

fn exception_class_name(env: &mut JNIEnv<'_>, throwable: &JThrowable<'_>) -> Option<String> {
    let class = env
        .call_method(throwable, "getClass", "()Ljava/lang/Class;", &[])
        .ok()?
        .l()
        .ok()?;
    let name = env
        .call_method(class, "getName", "()Ljava/lang/String;", &[])
        .ok()?
        .l()
        .ok()?;
    env.get_string(&JString::from(name)).ok().map(Into::into)
}

fn classify_exception(class: &str) -> Error {
    match class {
        "android.security.keystore.KeyPermanentlyInvalidatedException"
        | "java.security.UnrecoverableKeyException" => {
            Error::Authorization(AuthorizationError::CredentialInvalidated)
        }
        "android.security.keystore.UserNotAuthenticatedException" => {
            Error::Authorization(AuthorizationError::Denied)
        }
        "android.os.OperationCanceledException" => {
            Error::Authorization(AuthorizationError::Cancelled)
        }
        "android.security.keystore.StrongBoxUnavailableException" => Error::NotAvailable,
        other => Error::Hardware(other.to_owned()),
    }
}

fn sdk_version(env: &mut JNIEnv<'_>) -> Result<i32, Error> {
    env.get_static_field("android/os/Build$VERSION", "SDK_INT", "I")
        .map_err(jni_error)?
        .i()
        .map_err(jni_error)
}

fn key_store<'local>(env: &mut JNIEnv<'local>) -> Result<JObject<'local>, Error> {
    let provider = env.new_string("AndroidKeyStore").map_err(jni_error)?;
    let provider_object = JObject::from(provider);
    let store = env
        .call_static_method(
            "java/security/KeyStore",
            "getInstance",
            "(Ljava/lang/String;)Ljava/security/KeyStore;",
            &[JValue::Object(&provider_object)],
        )
        .map_err(jni_error)?
        .l()
        .map_err(jni_error)?;
    env.call_method(
        &store,
        "load",
        "(Ljava/security/KeyStore$LoadStoreParameter;)V",
        &[JValue::Object(&JObject::null())],
    )
    .map_err(jni_error)?;
    Ok(store)
}

fn get_or_create_key<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    alias: &str,
) -> Result<JObject<'local>, Error> {
    if contains_alias(env, store, alias)? {
        return get_existing_key(env, store, alias);
    }
    create_key(env, alias)?;
    get_existing_key(env, store, alias)
}

fn contains_alias(env: &mut JNIEnv<'_>, store: &JObject<'_>, alias: &str) -> Result<bool, Error> {
    let alias = env.new_string(alias).map_err(jni_error)?;
    let alias_object = JObject::from(alias);
    env.call_method(
        store,
        "containsAlias",
        "(Ljava/lang/String;)Z",
        &[JValue::Object(&alias_object)],
    )
    .map_err(jni_error)?
    .z()
    .map_err(jni_error)
}

fn get_existing_key<'local>(
    env: &mut JNIEnv<'local>,
    store: &JObject<'local>,
    alias: &str,
) -> Result<JObject<'local>, Error> {
    if !contains_alias(env, store, alias)? {
        return Err(Error::Authorization(
            AuthorizationError::CredentialInvalidated,
        ));
    }
    let alias = env.new_string(alias).map_err(jni_error)?;
    let alias_object = JObject::from(alias);
    let key = env
        .call_method(
            store,
            "getKey",
            "(Ljava/lang/String;[C)Ljava/security/Key;",
            &[
                JValue::Object(&alias_object),
                JValue::Object(&JObject::null()),
            ],
        )
        .map_err(jni_error)?
        .l()
        .map_err(jni_error)?;
    if key.is_null() {
        return Err(Error::Authorization(
            AuthorizationError::CredentialInvalidated,
        ));
    }
    Ok(key)
}

fn create_key(env: &mut JNIEnv<'_>, alias: &str) -> Result<(), Error> {
    let algorithm = env.new_string("AES").map_err(jni_error)?;
    let provider = env.new_string("AndroidKeyStore").map_err(jni_error)?;
    let algorithm_object = JObject::from(algorithm);
    let provider_object = JObject::from(provider);
    let generator = env
        .call_static_method(
            "javax/crypto/KeyGenerator",
            "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            &[
                JValue::Object(&algorithm_object),
                JValue::Object(&provider_object),
            ],
        )
        .map_err(jni_error)?
        .l()
        .map_err(jni_error)?;

    let alias = env.new_string(alias).map_err(jni_error)?;
    let alias_object = JObject::from(alias);
    let builder = env
        .new_object(
            "android/security/keystore/KeyGenParameterSpec$Builder",
            "(Ljava/lang/String;I)V",
            &[
                JValue::Object(&alias_object),
                JValue::Int(PURPOSE_ENCRYPT_DECRYPT),
            ],
        )
        .map_err(jni_error)?;

    call_builder_int(env, &builder, "setKeySize", 256)?;
    call_builder_strings(env, &builder, "setBlockModes", "GCM")?;
    call_builder_strings(env, &builder, "setEncryptionPaddings", "NoPadding")?;
    call_builder_bool(env, &builder, "setRandomizedEncryptionRequired", true)?;

    let spec = env
        .call_method(
            builder,
            "build",
            "()Landroid/security/keystore/KeyGenParameterSpec;",
            &[],
        )
        .map_err(jni_error)?
        .l()
        .map_err(jni_error)?;
    env.call_method(
        &generator,
        "init",
        "(Ljava/security/spec/AlgorithmParameterSpec;)V",
        &[JValue::Object(&spec)],
    )
    .map_err(jni_error)?;
    env.call_method(generator, "generateKey", "()Ljavax/crypto/SecretKey;", &[])
        .map(drop)
        .map_err(jni_error)
}

fn ensure_hardware_key(env: &mut JNIEnv<'_>, key: &JObject<'_>) -> Result<(), Error> {
    let algorithm = env
        .call_method(key, "getAlgorithm", "()Ljava/lang/String;", &[])
        .map_err(jni_error)?
        .l()
        .map_err(jni_error)?;
    let provider = env.new_string("AndroidKeyStore").map_err(jni_error)?;
    let provider_object = JObject::from(provider);
    let factory = env
        .call_static_method(
            "javax/crypto/SecretKeyFactory",
            "getInstance",
            "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/SecretKeyFactory;",
            &[JValue::Object(&algorithm), JValue::Object(&provider_object)],
        )
        .map_err(jni_error)?
        .l()
        .map_err(jni_error)?;
    let key_info_class = env
        .find_class("android/security/keystore/KeyInfo")
        .map_err(jni_error)?;
    let key_info_class_object = JObject::from(key_info_class);
    let info = env
        .call_method(
            factory,
            "getKeySpec",
            "(Ljava/security/Key;Ljava/lang/Class;)Ljava/security/spec/KeySpec;",
            &[JValue::Object(key), JValue::Object(&key_info_class_object)],
        )
        .map_err(jni_error)?
        .l()
        .map_err(jni_error)?;
    let inside_hardware = env
        .call_method(info, "isInsideSecureHardware", "()Z", &[])
        .map_err(jni_error)?
        .z()
        .map_err(jni_error)?;
    if inside_hardware {
        Ok(())
    } else {
        Err(Error::NotAvailable)
    }
}

fn cipher<'local>(env: &mut JNIEnv<'local>) -> Result<JObject<'local>, Error> {
    let transformation = env.new_string("AES/GCM/NoPadding").map_err(jni_error)?;
    let transformation_object = JObject::from(transformation);
    env.call_static_method(
        "javax/crypto/Cipher",
        "getInstance",
        "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
        &[JValue::Object(&transformation_object)],
    )
    .map_err(jni_error)?
    .l()
    .map_err(jni_error)
}

fn update_aad(
    env: &mut JNIEnv<'_>,
    cipher: &JObject<'_>,
    label_hash: [u8; LABEL_HASH_BYTES],
    policy: AccessPolicy,
) -> Result<(), Error> {
    let mut aad = Vec::with_capacity(LABEL_HASH_BYTES + 1);
    aad.extend_from_slice(&label_hash);
    aad.push(policy_id(policy));
    let aad = env.byte_array_from_slice(&aad).map_err(jni_error)?;
    let aad_object = JObject::from(aad);
    env.call_method(cipher, "updateAAD", "([B)V", &[JValue::Object(&aad_object)])
        .map(drop)
        .map_err(jni_error)
}

fn call_builder_int(
    env: &mut JNIEnv<'_>,
    builder: &JObject<'_>,
    method: &str,
    value: i32,
) -> Result<(), Error> {
    env.call_method(
        builder,
        method,
        "(I)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Int(value)],
    )
    .map(drop)
    .map_err(jni_error)
}

fn call_builder_bool(
    env: &mut JNIEnv<'_>,
    builder: &JObject<'_>,
    method: &str,
    value: bool,
) -> Result<(), Error> {
    env.call_method(
        builder,
        method,
        "(Z)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Bool(u8::from(value))],
    )
    .map(drop)
    .map_err(jni_error)
}

fn call_builder_strings(
    env: &mut JNIEnv<'_>,
    builder: &JObject<'_>,
    method: &str,
    value: &str,
) -> Result<(), Error> {
    let string_class: JClass<'_> = env.find_class("java/lang/String").map_err(jni_error)?;
    let values: JObjectArray<'_> = env
        .new_object_array(1, string_class, JObject::null())
        .map_err(jni_error)?;
    let value: JString<'_> = env.new_string(value).map_err(jni_error)?;
    env.set_object_array_element(&values, 0, value)
        .map_err(jni_error)?;
    let values_object = JObject::from(values);
    env.call_method(
        builder,
        method,
        "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
        &[JValue::Object(&values_object)],
    )
    .map(drop)
    .map_err(jni_error)
}

fn call_method<'local>(
    env: &mut JNIEnv<'local>,
    object: &JObject<'local>,
    name: &str,
    signature: &str,
    args: &[JValue<'local, '_>],
) -> Result<jni::objects::JValueOwned<'local>, Error> {
    env.call_method(object, name, signature, args)
        .map_err(jni_error)
}

fn encode_envelope(
    policy: AccessPolicy,
    label_hash: [u8; LABEL_HASH_BYTES],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Error> {
    if iv.is_empty() || iv.len() > MAX_IV_BYTES || ciphertext.len() > MAX_CIPHERTEXT_BYTES {
        return Err(Error::InvalidEnvelope(
            "Android Keystore output exceeds envelope limits".to_owned(),
        ));
    }
    let iv_len = u8::try_from(iv.len())
        .map_err(|_| Error::InvalidEnvelope("Android IV is too large".to_owned()))?;
    let ciphertext_len = u32::try_from(ciphertext.len())
        .map_err(|_| Error::InvalidEnvelope("Android ciphertext is too large".to_owned()))?;
    let mut output = Vec::with_capacity(HEADER_BYTES + iv.len() + ciphertext.len());
    output.extend_from_slice(MAGIC);
    output.push(VERSION);
    output.push(policy_id(policy));
    output.extend_from_slice(&label_hash);
    output.push(iv_len);
    output.extend_from_slice(&ciphertext_len.to_be_bytes());
    output.extend_from_slice(iv);
    output.extend_from_slice(ciphertext);
    Ok(output)
}

struct ParsedEnvelope<'a> {
    iv: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse_envelope(
    input: &[u8],
    expected_label_hash: [u8; LABEL_HASH_BYTES],
    expected_policy: AccessPolicy,
) -> Result<ParsedEnvelope<'_>, Error> {
    if input.len() < HEADER_BYTES || &input[..MAGIC.len()] != MAGIC {
        return Err(Error::InvalidEnvelope(
            "missing Android Keystore envelope header".to_owned(),
        ));
    }
    if input[MAGIC.len()] != VERSION {
        return Err(Error::InvalidEnvelope(format!(
            "unsupported Android envelope version {}",
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
    let iv_len = usize::from(input[label_end]);
    let ciphertext_len_bytes = input
        .get(label_end + 1..HEADER_BYTES)
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| Error::InvalidEnvelope("truncated Android envelope".to_owned()))?;
    let ciphertext_len = u32::from_be_bytes(ciphertext_len_bytes) as usize;
    if iv_len == 0 || iv_len > MAX_IV_BYTES || ciphertext_len > MAX_CIPHERTEXT_BYTES {
        return Err(Error::InvalidEnvelope(
            "Android envelope exceeds size limits".to_owned(),
        ));
    }
    let iv_end = HEADER_BYTES
        .checked_add(iv_len)
        .ok_or_else(|| Error::InvalidEnvelope("envelope length overflow".to_owned()))?;
    let end = iv_end
        .checked_add(ciphertext_len)
        .ok_or_else(|| Error::InvalidEnvelope("envelope length overflow".to_owned()))?;
    if end != input.len() {
        return Err(Error::InvalidEnvelope(
            "Android envelope lengths do not match its contents".to_owned(),
        ));
    }
    Ok(ParsedEnvelope {
        iv: &input[HEADER_BYTES..iv_end],
        ciphertext: &input[iv_end..],
    })
}

fn alias(label_hash: [u8; LABEL_HASH_BYTES], policy: AccessPolicy) -> String {
    use std::fmt::Write as _;

    let mut output = format!("hardwareseal.{}.", policy_id(policy));
    for byte in label_hash {
        write!(output, "{byte:02x}").expect("writing to a string cannot fail");
    }
    output
}

const fn policy_id(policy: AccessPolicy) -> u8 {
    match policy {
        AccessPolicy::None => 0,
        AccessPolicy::Biometric => 1,
    }
}

fn jni_error(error: impl std::fmt::Display) -> Error {
    Error::Hardware(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_binds_policy_and_label() {
        let label = [3; LABEL_HASH_BYTES];
        let envelope =
            encode_envelope(AccessPolicy::None, label, &[1; 12], &[2; 32]).expect("encode");
        let parsed = parse_envelope(&envelope, label, AccessPolicy::None).expect("parse");
        assert_eq!(parsed.iv, &[1; 12]);
        assert_eq!(parsed.ciphertext, &[2; 32]);
        assert!(parse_envelope(&envelope, [4; LABEL_HASH_BYTES], AccessPolicy::None).is_err());
        assert!(parse_envelope(&envelope, label, AccessPolicy::Biometric).is_err());
    }

    #[test]
    fn keystore_exceptions_have_stable_authorization_categories() {
        assert!(matches!(
            classify_exception("android.security.keystore.KeyPermanentlyInvalidatedException"),
            Error::Authorization(AuthorizationError::CredentialInvalidated)
        ));
        assert!(matches!(
            classify_exception("java.security.UnrecoverableKeyException"),
            Error::Authorization(AuthorizationError::CredentialInvalidated)
        ));
        assert!(matches!(
            classify_exception("android.security.keystore.UserNotAuthenticatedException"),
            Error::Authorization(AuthorizationError::Denied)
        ));
        assert!(matches!(
            classify_exception("android.os.OperationCanceledException"),
            Error::Authorization(AuthorizationError::Cancelled)
        ));
        assert!(matches!(
            classify_exception("android.security.keystore.StrongBoxUnavailableException"),
            Error::NotAvailable
        ));
        assert!(matches!(
            classify_exception("java.lang.IllegalStateException"),
            Error::Hardware(_)
        ));
    }
}

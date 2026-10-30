#![allow(unsafe_code)]

use hardwareseal::{AuthorizationError, Error};
use jni::JNIEnv;
use jni::objects::{GlobalRef, JByteArray, JByteBuffer, JClass, JObject, JValue};
use jni::sys::jint;
use std::sync::OnceLock;
use zeroize::Zeroizing;

static CONTEXT: OnceLock<GlobalRef> = OnceLock::new();
static BIOMETRICS: OnceLock<GlobalRef> = OnceLock::new();

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_cachix_factorseal_core_NativeCore_initialize(
    mut env: JNIEnv<'_>,
    _class: JClass<'_>,
    context: JObject<'_>,
) {
    if CONTEXT.get().is_some() {
        return;
    }
    let (Ok(vm), Ok(global)) = (env.get_java_vm(), env.new_global_ref(context)) else {
        return;
    };
    let context = global.as_obj().as_raw();
    if CONTEXT.set(global).is_ok() {
        unsafe {
            ndk_context::initialize_android_context(
                vm.get_java_vm_pointer().cast(),
                context.cast(),
            );
        }
    }
    match env
        .find_class("com/cachix/factorseal/android/Biometrics")
        .and_then(|class| env.new_global_ref(class))
    {
        Ok(class) => {
            if BIOMETRICS.set(class).is_ok() {
                hardwareseal::set_android_authorizer(authorize);
            }
        }
        Err(_) => {
            let _ = env.exception_clear();
        }
    }
}

fn authorize(env: &mut JNIEnv<'_>, cipher: &JObject<'_>) -> Result<(), Error> {
    let class = BIOMETRICS
        .get()
        .ok_or(Error::Authorization(AuthorizationError::UiUnavailable))?;
    let code = env
        .call_static_method(
            <&JClass>::from(class.as_obj()),
            "authorize",
            "(Ljavax/crypto/Cipher;)I",
            &[JValue::Object(cipher)],
        )
        .and_then(jni::objects::JValueGen::i);
    match code {
        Ok(0) => Ok(()),
        Ok(1) => Err(Error::Authorization(AuthorizationError::Cancelled)),
        Ok(2) => Err(Error::Authorization(AuthorizationError::Denied)),
        Ok(3) => Err(Error::Authorization(AuthorizationError::UiUnavailable)),
        Ok(other) => Err(Error::Hardware(format!(
            "the biometric prompt returned {other}"
        ))),
        Err(error) => {
            let _ = env.exception_clear();
            Err(Error::Hardware(error.to_string()))
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_cachix_factorseal_core_NativeCore_call<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    request: JByteArray<'local>,
) -> JByteArray<'local> {
    let Ok(request) = env.convert_byte_array(&request).map(Zeroizing::new) else {
        return JByteArray::default();
    };
    let response = crate::call(&request);
    env.byte_array_from_slice(&response).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_cachix_factorseal_core_NativeCore_scan<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pixels: JByteBuffer<'local>,
    width: jint,
    height: jint,
    stride: jint,
) -> JByteArray<'local> {
    let response = match (
        env.get_direct_buffer_address(&pixels),
        env.get_direct_buffer_capacity(&pixels),
        usize::try_from(width),
        usize::try_from(height),
        usize::try_from(stride),
    ) {
        (Ok(address), Ok(capacity), Ok(width), Ok(height), Ok(stride)) if !address.is_null() => {
            crate::scan(
                unsafe { std::slice::from_raw_parts(address, capacity) },
                width,
                height,
                stride,
            )
        }
        _ => crate::scan(&[], 0, 0, 0),
    };
    env.byte_array_from_slice(&response).unwrap_or_default()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_com_cachix_factorseal_core_NativeCore_seal(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
) {
    crate::seal();
}

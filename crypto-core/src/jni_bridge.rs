use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use jni::objects::{JClass, JString};
use jni::sys::jstring;
use jni::JNIEnv;

fn get_string(env: &mut JNIEnv, input: &JString) -> String {
    env.get_string(input).map(|s| s.into()).unwrap_or_default()
}

#[no_mangle]
pub extern "system" fn Java_com_securevault_mobile_domain_crypto_RustCryptoCore_nativeDeriveMasterKey(
    mut env: JNIEnv,
    _class: JClass,
    j_password: JString,
    j_salt_b64: JString,
    iterations: i32,
    memory: i32,
    parallelism: i32,
) -> jstring {
    let password = get_string(&mut env, &j_password);
    let salt_b64 = get_string(&mut env, &j_salt_b64);
    let salt = match STANDARD.decode(&salt_b64) {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };
    let params = KdfParams { iterations: iterations as u32, memory_kib: memory as u32, parallelism: parallelism as u32 };
    match derive_master_key(&password, &salt, &params) {
        Ok(mk) => env.new_string(&b64e(&mk)).expect("Java string").into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[no_mangle]
pub extern "system" fn Java_com_securevault_mobile_domain_crypto_RustCryptoCore_nativeDeriveAuthHash(
    mut env: JNIEnv,
    _class: JClass,
    j_master_key_b64: JString,
) -> jstring {
    let mk_b64 = get_string(&mut env, &j_master_key_b64);
    let mk = match STANDARD.decode(&mk_b64) {
        Ok(m) => m,
        Err(_) => return std::ptr::null_mut(),
    };
    env.new_string(&derive_auth_hash(&mk)).expect("Java string").into_raw()
}

#[no_mangle]
pub extern "system" fn Java_com_securevault_mobile_domain_crypto_RustCryptoCore_nativeDeriveKek(
    mut env: JNIEnv,
    _class: JClass,
    j_master_key_b64: JString,
) -> jstring {
    let mk_b64 = get_string(&mut env, &j_master_key_b64);
    let mk = match STANDARD.decode(&mk_b64) {
        Ok(m) => m,
        Err(_) => return std::ptr::null_mut(),
    };
    let kek = derive_kek(&mk);
    env.new_string(&STANDARD.encode(&kek)).expect("Java string").into_raw()
}

// JVM test bridge — matches NativeBridge.java in androidUnitTest
#[no_mangle]
pub extern "system" fn Java_com_securevault_mobile_data_local_NativeBridge_nativeDeriveMasterKey(
    mut env: JNIEnv,
    _class: JClass,
    j_password: JString,
    j_salt_b64: JString,
    iterations: i32,
    memory: i32,
    parallelism: i32,
) -> jstring {
    Java_com_securevault_mobile_domain_crypto_RustCryptoCore_nativeDeriveMasterKey(env, _class, j_password, j_salt_b64, iterations, memory, parallelism)
}

#[no_mangle]
pub extern "system" fn Java_com_securevault_mobile_data_local_NativeBridge_nativeDeriveAuthHash(
    mut env: JNIEnv,
    _class: JClass,
    j_master_key_b64: JString,
) -> jstring {
    Java_com_securevault_mobile_domain_crypto_RustCryptoCore_nativeDeriveAuthHash(env, _class, j_master_key_b64)
}

#[no_mangle]
pub extern "system" fn Java_com_securevault_mobile_data_local_NativeBridge_nativeDeriveKek(
    mut env: JNIEnv,
    _class: JClass,
    j_master_key_b64: JString,
) -> jstring {
    Java_com_securevault_mobile_domain_crypto_RustCryptoCore_nativeDeriveKek(env, _class, j_master_key_b64)
}

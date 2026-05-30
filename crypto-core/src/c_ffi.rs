use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

fn b64_encode(bytes: &[u8]) -> CString {
    CString::new(STANDARD.encode(bytes)).unwrap_or_default()
}

/// # Safety
/// `ptr` must be a valid null-terminated C string pointer.
unsafe fn cstr_to_str<'a>(ptr: *const c_char) -> &'a str {
    CStr::from_ptr(ptr).to_str().unwrap_or_default()
}

/// Derive a master key via Argon2id.
///
/// # Safety
/// `password` and `salt_b64` must be valid null-terminated C strings.
/// Returns base64-encoded master key — must be freed with `securevault_free_string`.
#[no_mangle]
pub unsafe extern "C" fn securevault_derive_master_key(
    password: *const c_char,
    salt_b64: *const c_char,
    iterations: i32,
    memory: i32,
    parallelism: i32,
) -> *mut c_char {
    let password = cstr_to_str(password);
    let salt = match STANDARD.decode(cstr_to_str(salt_b64)) {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let params = KdfParams { iterations: iterations as u32, memory_kib: memory as u32, parallelism: parallelism as u32 };
    match derive_master_key(password, &salt, &params) {
        Ok(mk) => b64_encode(&mk).into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Derive an auth hash from a master key.
///
/// # Safety
/// `master_key_b64` must be a valid null-terminated base64 C string.
#[no_mangle]
pub unsafe extern "C" fn securevault_derive_auth_hash(
    master_key_b64: *const c_char,
) -> *mut c_char {
    let mk = match STANDARD.decode(cstr_to_str(master_key_b64)) {
        Ok(m) => m,
        Err(_) => return ptr::null_mut(),
    };
    CString::new(derive_auth_hash(&mk)).unwrap_or_default().into_raw()
}

/// Derive a KEK from a master key.
///
/// # Safety
/// `master_key_b64` must be a valid null-terminated base64 C string.
#[no_mangle]
pub unsafe extern "C" fn securevault_derive_kek(
    master_key_b64: *const c_char,
) -> *mut c_char {
    let mk = match STANDARD.decode(cstr_to_str(master_key_b64)) {
        Ok(m) => m,
        Err(_) => return ptr::null_mut(),
    };
    b64_encode(&derive_kek(&mk)).into_raw()
}

/// Wrap a vault key with a KEK using AES-256-GCM.
/// Returns base64( nonce[12] || ciphertext || tag[16] ) — must be freed with `securevault_free_string`.
///
/// # Safety
/// `kek_b64` and `vault_key_b64` must be valid null-terminated base64 C strings.
#[no_mangle]
pub unsafe extern "C" fn securevault_wrap_vault_key(
    kek_b64: *const c_char,
    vault_key_b64: *const c_char,
) -> *mut c_char {
    let kek = match STANDARD.decode(cstr_to_str(kek_b64)) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };
    let vk = match STANDARD.decode(cstr_to_str(vault_key_b64)) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };
    match wrap_vault_key(&kek, &vk) {
        Ok(w) => CString::new(w).unwrap_or_default().into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Unwrap a vault key with a KEK using AES-256-GCM.
/// Returns base64 of the vault key — must be freed with `securevault_free_string`.
///
/// # Safety
/// `kek_b64` and `wrapped_b64` must be valid null-terminated base64 C strings.
#[no_mangle]
pub unsafe extern "C" fn securevault_unwrap_vault_key(
    kek_b64: *const c_char,
    wrapped_b64: *const c_char,
) -> *mut c_char {
    let kek = match STANDARD.decode(cstr_to_str(kek_b64)) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };
    match unwrap_vault_key(&kek, cstr_to_str(wrapped_b64)) {
        Ok(vk) => b64_encode(&vk).into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Encrypt a vault entry with AES-256-GCM.
/// Returns JSON `{"encryptedData":"v1:...","iv":"..."}` — must be freed with `securevault_free_string`.
///
/// # Safety
/// `vault_key_b64` and `plaintext_json` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn securevault_encrypt_entry(
    vault_key_b64: *const c_char,
    plaintext_json: *const c_char,
) -> *mut c_char {
    let vk = match STANDARD.decode(cstr_to_str(vault_key_b64)) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };
    match encrypt_entry(&vk, cstr_to_str(plaintext_json)) {
        Ok(entry) => {
            let json = serde_json::to_string(&entry).unwrap_or_default();
            CString::new(json).unwrap_or_default().into_raw()
        }
        Err(_) => ptr::null_mut(),
    }
}

/// Decrypt a vault entry with AES-256-GCM.
/// Returns the plaintext JSON string — must be freed with `securevault_free_string`.
///
/// # Safety
/// `vault_key_b64`, `encrypted_data`, and `iv` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn securevault_decrypt_entry(
    vault_key_b64: *const c_char,
    encrypted_data: *const c_char,
    iv: *const c_char,
) -> *mut c_char {
    let vk = match STANDARD.decode(cstr_to_str(vault_key_b64)) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };
    let entry = EntryCiphertext {
        encrypted_data: cstr_to_str(encrypted_data).to_string(),
        iv: cstr_to_str(iv).to_string(),
    };
    match decrypt_entry(&vk, &entry) {
        Ok(pt) => CString::new(pt).unwrap_or_default().into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Encrypt a local field with AES-256-GCM.
/// Returns `"v1:" + base64(nonce || ciphertext || tag)` — must be freed with `securevault_free_string`.
///
/// # Safety
/// `vault_key_b64` and `plaintext` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn securevault_encrypt_field(
    vault_key_b64: *const c_char,
    plaintext: *const c_char,
) -> *mut c_char {
    let vk = match STANDARD.decode(cstr_to_str(vault_key_b64)) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };
    match encrypt_field(&vk, cstr_to_str(plaintext)) {
        Ok(ct) => CString::new(ct).unwrap_or_default().into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Decrypt a local field with AES-256-GCM.
/// Returns the plaintext — must be freed with `securevault_free_string`.
///
/// # Safety
/// `vault_key_b64` and `ciphertext` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn securevault_decrypt_field(
    vault_key_b64: *const c_char,
    ciphertext: *const c_char,
) -> *mut c_char {
    let vk = match STANDARD.decode(cstr_to_str(vault_key_b64)) {
        Ok(b) => b,
        Err(_) => return ptr::null_mut(),
    };
    match decrypt_field(&vk, cstr_to_str(ciphertext)) {
        Ok(pt) => CString::new(pt).unwrap_or_default().into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a string returned by any `securevault_*` function.
///
/// # Safety
/// `ptr` must be a pointer previously returned by a `securevault_*` function,
/// or null (which is safely handled).
#[no_mangle]
pub unsafe extern "C" fn securevault_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

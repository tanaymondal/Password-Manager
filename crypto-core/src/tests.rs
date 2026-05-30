use crate::*;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use std::path::PathBuf;

fn load_vectors() -> Option<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../test-vectors/vectors.json");
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn parse_params(v: &Value) -> KdfParams {
    let p = &v["params"];
    if p.is_object() {
        KdfParams {
            iterations: p["iterations"].as_u64().unwrap() as u32,
            memory_kib: p["memory_kib"].as_u64().unwrap() as u32,
            parallelism: p["parallelism"].as_u64().unwrap() as u32,
        }
    } else {
        DEFAULT_PARAMS
    }
}

fn dec(s: &str) -> Vec<u8> {
    STANDARD.decode(s).unwrap()
}

// ---------------------------------------------------------------------------
// CryptoError::Display tests
// ---------------------------------------------------------------------------

#[test]
fn display_invalid_key_length() {
    assert_eq!(format!("{}", CryptoError::InvalidKeyLength), "invalid key length");
}

#[test]
fn display_invalid_input() {
    let e = CryptoError::InvalidInput("bad data");
    assert_eq!(format!("{e}"), "invalid input: bad data");
}

#[test]
fn display_base64() {
    assert_eq!(format!("{}", CryptoError::Base64), "base64 decode failed");
}

#[test]
fn display_kdf() {
    assert_eq!(format!("{}", CryptoError::Kdf), "key derivation failed");
}

#[test]
fn display_encrypt() {
    assert_eq!(format!("{}", CryptoError::Encrypt), "encryption failed");
}

#[test]
fn display_decryption_failed() {
    assert_eq!(format!("{}", CryptoError::DecryptionFailed), "decryption failed");
}

#[test]
fn display_rng() {
    assert_eq!(format!("{}", CryptoError::Rng), "RNG failure");
}

#[test]
fn error_trait_impl() {
    let e = CryptoError::Base64;
    let err: &dyn std::error::Error = &e;
    assert_eq!(err.to_string(), "base64 decode failed");
}

// ---------------------------------------------------------------------------
// C FFI tests (host platform only)
// ---------------------------------------------------------------------------

#[test]
fn cffi_derive_auth_hash_returns_base64() {
    let password = std::ffi::CString::new("testpassword").unwrap();
    let salt = std::ffi::CString::new("saltsalt1234").unwrap();
    let result = unsafe {
        crate::c_ffi::securevault_derive_auth_hash(
            password.as_ptr(),
            salt.as_ptr(),
            3, 8192, 1,
        )
    };
    assert!(!result.is_null());
    let output = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { crate::c_ffi::securevault_free_string(result) };
    assert_eq!(output.len(), 44);
    STANDARD.decode(&output).unwrap();
}

#[test]
fn cffi_derive_auth_hash_deterministic() {
    let password = std::ffi::CString::new("test").unwrap();
    let salt = std::ffi::CString::new("saltsalt1234").unwrap();
    let r1 = unsafe {
        let p = crate::c_ffi::securevault_derive_auth_hash(
            password.as_ptr(), salt.as_ptr(), 3, 8192, 1,
        );
        let s = std::ffi::CStr::from_ptr(p).to_str().unwrap().to_string();
        crate::c_ffi::securevault_free_string(p);
        s
    };
    let r2 = unsafe {
        let p = crate::c_ffi::securevault_derive_auth_hash(
            password.as_ptr(), salt.as_ptr(), 3, 8192, 1,
        );
        let s = std::ffi::CStr::from_ptr(p).to_str().unwrap().to_string();
        crate::c_ffi::securevault_free_string(p);
        s
    };
    assert_eq!(r1, r2);
}

#[test]
fn cffi_derive_auth_hash_differs_for_different_passwords() {
    let salt = std::ffi::CString::new("saltsalt1234").unwrap();
    let pw1 = std::ffi::CString::new("password1").unwrap();
    let pw2 = std::ffi::CString::new("password2").unwrap();
    let r1 = unsafe {
        let p = crate::c_ffi::securevault_derive_auth_hash(
            pw1.as_ptr(), salt.as_ptr(), 3, 8192, 1,
        );
        let s = std::ffi::CStr::from_ptr(p).to_str().unwrap().to_string();
        crate::c_ffi::securevault_free_string(p);
        s
    };
    let r2 = unsafe {
        let p = crate::c_ffi::securevault_derive_auth_hash(
            pw2.as_ptr(), salt.as_ptr(), 3, 8192, 1,
        );
        let s = std::ffi::CStr::from_ptr(p).to_str().unwrap().to_string();
        crate::c_ffi::securevault_free_string(p);
        s
    };
    assert_ne!(r1, r2);
}

#[test]
fn cffi_derive_kek_returns_base64() {
    let password = std::ffi::CString::new("testpassword").unwrap();
    let salt_b64 = std::ffi::CString::new(STANDARD.encode(b"0123456789abcdef")).unwrap();
    let result = unsafe {
        crate::c_ffi::securevault_derive_kek(
            password.as_ptr(),
            salt_b64.as_ptr(),
            3, 8192, 1,
        )
    };
    assert!(!result.is_null());
    let output = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { crate::c_ffi::securevault_free_string(result) };
    let decoded = STANDARD.decode(&output).unwrap();
    assert_eq!(decoded.len(), 32);
}

#[test]
fn cffi_free_null_is_safe() {
    unsafe { crate::c_ffi::securevault_free_string(std::ptr::null_mut()) };
}

#[test]
fn cffi_derive_auth_hash_returns_null_on_error() {
    // Invalid params (memory too low) should return null
    let password = std::ffi::CString::new("test").unwrap();
    let salt = std::ffi::CString::new("salt").unwrap();
    let result = unsafe {
        crate::c_ffi::securevault_derive_auth_hash(
            password.as_ptr(),
            salt.as_ptr(),
            0, 1, 0, // invalid params
        )
    };
    assert!(result.is_null());
}

#[test]
fn cffi_derive_kek_returns_null_on_error() {
    let password = std::ffi::CString::new("test").unwrap();
    let salt_b64 = std::ffi::CString::new("!!!invalid-base64!!!").unwrap();
    let result = unsafe {
        crate::c_ffi::securevault_derive_kek(
            password.as_ptr(),
            salt_b64.as_ptr(),
            3, 8192, 1,
        )
    };
    assert!(result.is_null());
}

#[test]
fn cffi_derive_kek_returns_base64_and_free() {
    let password = std::ffi::CString::new("testpassword").unwrap();
    let salt_b64 = std::ffi::CString::new(STANDARD.encode(b"0123456789abcdef")).unwrap();
    let result = unsafe {
        crate::c_ffi::securevault_derive_kek(
            password.as_ptr(),
            salt_b64.as_ptr(),
            3, 8192, 1,
        )
    };
    assert!(!result.is_null());
    let output = unsafe { std::ffi::CStr::from_ptr(result) }
        .to_str()
        .unwrap()
        .to_string();
    unsafe { crate::c_ffi::securevault_free_string(result) };
    let decoded = STANDARD.decode(&output).unwrap();
    assert_eq!(decoded.len(), 32);
}

#[test]
fn cffi_derive_kek_deterministic() {
    let password = std::ffi::CString::new("test").unwrap();
    let salt_b64 = std::ffi::CString::new(STANDARD.encode(b"0123456789abcdef")).unwrap();
    let r1 = unsafe {
        let p = crate::c_ffi::securevault_derive_kek(
            password.as_ptr(), salt_b64.as_ptr(), 3, 8192, 1,
        );
        let s = std::ffi::CStr::from_ptr(p).to_str().unwrap().to_string();
        crate::c_ffi::securevault_free_string(p);
        s
    };
    let r2 = unsafe {
        let p = crate::c_ffi::securevault_derive_kek(
            password.as_ptr(), salt_b64.as_ptr(), 3, 8192, 1,
        );
        let s = std::ffi::CStr::from_ptr(p).to_str().unwrap().to_string();
        crate::c_ffi::securevault_free_string(p);
        s
    };
    assert_eq!(r1, r2);
}

fn nonce12(s: &str) -> [u8; 12] {
    dec(s).try_into().expect("nonce must be 12 bytes")
}

#[test]
fn golden_vectors_exact_bytes() {
    let Some(root) = load_vectors() else {
        eprintln!("test-vectors/vectors.json not generated — skipping. Run: cd test-vectors && node generate.mjs > vectors.json");
        return;
    };
    let vectors = root["vectors"].as_array().expect("vectors array");
    assert!(!vectors.is_empty(), "no vectors found");

    for v in vectors {
        let name = v["name"].as_str().unwrap_or("<unnamed>");
        let op = v["op"].as_str().expect("op");
        let inp = &v["input"];
        let exp = &v["expected"];

        match op {
            "derive_auth_hash" => {
                let got = derive_auth_hash(
                    inp["password"].as_str().unwrap(),
                    inp["salt_str"].as_str().unwrap(),
                    &parse_params(v),
                )
                .unwrap();
                assert_eq!(got, exp["auth_hash_b64"].as_str().unwrap(), "{name}");
            }
            "derive_kek" => {
                let got = derive_kek(
                    inp["password"].as_str().unwrap(),
                    inp["salt_b64"].as_str().unwrap(),
                    &parse_params(v),
                )
                .unwrap();
                assert_eq!(STANDARD.encode(got), exp["kek_raw_b64"].as_str().unwrap(), "{name}");
            }
            "wrap_vault_key" => {
                let got = wrap_vault_key_with_nonce(
                    &dec(inp["kek_raw_b64"].as_str().unwrap()),
                    &dec(inp["vault_key_raw_b64"].as_str().unwrap()),
                    &nonce12(inp["nonce_b64"].as_str().unwrap()),
                )
                .unwrap();
                assert_eq!(got, exp["wrapped_b64"].as_str().unwrap(), "{name}");
            }
            "encrypt_entry" => {
                let got = encrypt_entry_with_nonce(
                    &dec(inp["vault_key_raw_b64"].as_str().unwrap()),
                    inp["plaintext_json"].as_str().unwrap(),
                    &nonce12(inp["nonce_b64"].as_str().unwrap()),
                )
                .unwrap();
                assert_eq!(got.encrypted_data, exp["encrypted_data"].as_str().unwrap(), "{name} data");
                assert_eq!(got.iv, exp["iv"].as_str().unwrap(), "{name} iv");
            }
            "encrypt_field" => {
                let got = encrypt_field_with_nonce(
                    &dec(inp["vault_key_raw_b64"].as_str().unwrap()),
                    inp["plaintext"].as_str().unwrap(),
                    &nonce12(inp["nonce_b64"].as_str().unwrap()),
                )
                .unwrap();
                assert_eq!(got, exp["ciphertext"].as_str().unwrap(), "{name}");
            }
            other => panic!("unknown op in vectors.json: {other}"),
        }
    }
}

#[test]
fn generate_vault_key_is_32_bytes() {
    let k = generate_vault_key().unwrap();
    assert_eq!(k.len(), 32);
}

#[test]
fn generate_vault_key_is_unique() {
    let k1 = generate_vault_key().unwrap();
    let k2 = generate_vault_key().unwrap();
    assert_ne!(k1, k2);
}

#[test]
fn generate_salt_is_valid_base64() {
    let s = generate_salt().unwrap();
    let decoded = STANDARD.decode(&s).unwrap();
    assert_eq!(decoded.len(), 16);
}

#[test]
fn derive_auth_hash_deterministic() {
    let p = KdfParams { iterations: 3, memory_kib: 8192, parallelism: 1 };
    let h1 = derive_auth_hash("testpassword", "saltsalt1234", &p).unwrap();
    let h2 = derive_auth_hash("testpassword", "saltsalt1234", &p).unwrap();
    assert_eq!(h1, h2);
}

#[test]
fn derive_auth_hash_differs_for_different_passwords() {
    let p = KdfParams { iterations: 3, memory_kib: 8192, parallelism: 1 };
    let h1 = derive_auth_hash("password1", "saltsalt1234", &p).unwrap();
    let h2 = derive_auth_hash("password2", "saltsalt1234", &p).unwrap();
    assert_ne!(h1, h2);
}

#[test]
fn derive_kek_deterministic() {
    let p = KdfParams { iterations: 2, memory_kib: 8192, parallelism: 1 };
    let salt = generate_salt().unwrap();
    let k1 = derive_kek("test", &salt, &p).unwrap();
    let k2 = derive_kek("test", &salt, &p).unwrap();
    assert_eq!(k1, k2);
}

#[test]
fn derive_kek_is_32_bytes() {
    let p = KdfParams { iterations: 2, memory_kib: 8192, parallelism: 1 };
    let salt = generate_salt().unwrap();
    let kek = derive_kek("test", &salt, &p).unwrap();
    assert_eq!(kek.len(), 32);
}

#[test]
fn derive_kek_invalid_base64_returns_error() {
    let p = KdfParams { iterations: 2, memory_kib: 8192, parallelism: 1 };
    let result = derive_kek("test", "not-valid-base64!!!", &p);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), CryptoError::Base64);
}

#[test]
fn wrap_unwrap_vault_key_round_trip() {
    let p = KdfParams { iterations: 2, memory_kib: 8192, parallelism: 1 };
    let salt = generate_salt().unwrap();
    let kek = derive_kek("password", &salt, &p).unwrap();
    let vk = generate_vault_key().unwrap();
    let wrapped = wrap_vault_key(&kek, &vk).unwrap();
    let unwrapped = unwrap_vault_key(&kek, &wrapped).unwrap();
    assert_eq!(unwrapped, vk);
}

#[test]
fn wrap_vault_key_produces_unique_output() {
    let p = KdfParams { iterations: 2, memory_kib: 8192, parallelism: 1 };
    let salt = generate_salt().unwrap();
    let kek = derive_kek("password", &salt, &p).unwrap();
    let vk = generate_vault_key().unwrap();
    let w1 = wrap_vault_key(&kek, &vk).unwrap();
    let w2 = wrap_vault_key(&kek, &vk).unwrap();
    assert_ne!(w1, w2);
}

#[test]
fn unwrap_vault_key_wrong_kek_returns_error() {
    let p = KdfParams { iterations: 2, memory_kib: 8192, parallelism: 1 };
    let salt1 = generate_salt().unwrap();
    let salt2 = generate_salt().unwrap();
    let kek1 = derive_kek("password1", &salt1, &p).unwrap();
    let kek2 = derive_kek("password2", &salt2, &p).unwrap();
    let vk = generate_vault_key().unwrap();
    let wrapped = wrap_vault_key(&kek1, &vk).unwrap();
    let result = unwrap_vault_key(&kek2, &wrapped);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
}

#[test]
fn unwrap_vault_key_tampered_data_returns_error() {
    let p = KdfParams { iterations: 2, memory_kib: 8192, parallelism: 1 };
    let salt = generate_salt().unwrap();
    let kek = derive_kek("password", &salt, &p).unwrap();
    let vk = generate_vault_key().unwrap();
    let wrapped_str = wrap_vault_key(&kek, &vk).unwrap();
    let mut decoded = STANDARD.decode(&wrapped_str).unwrap();
    // Flip a bit in the ciphertext portion (after the 12-byte nonce)
    let pos = 15;
    if pos < decoded.len() {
        decoded[pos] ^= 0xff;
    }
    let tampered = STANDARD.encode(&decoded);
    let result = unwrap_vault_key(&kek, &tampered);
    assert!(result.is_err());
}

#[test]
fn unwrap_vault_key_too_short_returns_error() {
    let kek = [0u8; 32];
    let result = unwrap_vault_key(&kek, &STANDARD.encode([0u8; 5]));
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), CryptoError::InvalidInput("wrapped key too short"));
}

#[test]
fn encrypt_decrypt_entry_round_trip() {
    let vk = generate_vault_key().unwrap();
    let json = r#"{"username":"alice","password":"hunter2"}"#;
    let ct = encrypt_entry(&vk, json).unwrap();
    assert!(ct.encrypted_data.starts_with("v1:"));
    let pt = decrypt_entry(&vk, &ct).unwrap();
    assert_eq!(pt, json);
}

#[test]
fn decrypt_entry_wrong_key_returns_error() {
    let vk1 = generate_vault_key().unwrap();
    let vk2 = generate_vault_key().unwrap();
    let ct = encrypt_entry(&vk1, r#"{"a":1}"#).unwrap();
    let result = decrypt_entry(&vk2, &ct);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), CryptoError::DecryptionFailed);
}

#[test]
fn decrypt_entry_tampered_returns_error() {
    let vk = generate_vault_key().unwrap();
    let ct = encrypt_entry(&vk, r#"{"a":1}"#).unwrap();
    let mut data = ct.encrypted_data.into_bytes();
    if let Some(b) = data.last_mut() {
        *b ^= 1;
    }
    let tampered = EntryCiphertext {
        encrypted_data: String::from_utf8(data).unwrap(),
        iv: ct.iv,
    };
    let result = decrypt_entry(&vk, &tampered);
    assert!(result.is_err());
}

#[test]
fn decrypt_entry_invalid_utf8_returns_error() {
    let vk = generate_vault_key().unwrap();
    let nonce = [0u8; 12];
    let ct = encrypt_entry_with_nonce(&vk, "hello", &nonce).unwrap();
    // tamper to produce invalid UTF-8
    let raw = crate::b64d(ct.encrypted_data.strip_prefix("v1:").unwrap()).unwrap();
    let garbage = crate::b64d("////").unwrap();
    let bad = EntryCiphertext {
                encrypted_data: format!("v1:{}", STANDARD.encode(&garbage)),
        iv: ct.iv,
    };
    let result = decrypt_entry(&vk, &bad);
    assert!(result.is_err());
}

#[test]
fn encrypt_decrypt_field_round_trip() {
    let vk = generate_vault_key().unwrap();
    let ct = encrypt_field(&vk, "my secret data").unwrap();
    assert!(ct.starts_with("v1:"));
    let pt = decrypt_field(&vk, &ct).unwrap();
    assert_eq!(pt, "my secret data");
}

#[test]
fn encrypt_field_empty_returns_empty() {
    let vk = generate_vault_key().unwrap();
    let ct = encrypt_field(&vk, "").unwrap();
    assert_eq!(ct, "");
    let pt = decrypt_field(&vk, "").unwrap();
    assert_eq!(pt, "");
}

#[test]
fn decrypt_field_wrong_key_returns_error() {
    let vk1 = generate_vault_key().unwrap();
    let vk2 = generate_vault_key().unwrap();
    let ct = encrypt_field(&vk1, "secret").unwrap();
    let result = decrypt_field(&vk2, &ct);
    assert!(result.is_err());
}

#[test]
fn entry_encrypts_differently_each_time() {
    let vk = generate_vault_key().unwrap();
    let json = r#"{"a":1}"#;
    let c1 = encrypt_entry(&vk, json).unwrap();
    let c2 = encrypt_entry(&vk, json).unwrap();
    assert_ne!(c1.encrypted_data, c2.encrypted_data);
    assert_ne!(c1.iv, c2.iv);
}

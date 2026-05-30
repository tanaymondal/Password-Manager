use crate::*;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct WasmKdfParams {
    iterations: u32,
    memory_kib: u32,
    parallelism: u32,
}

#[wasm_bindgen]
impl WasmKdfParams {
    #[wasm_bindgen(constructor)]
    pub fn new(iterations: u32, memory_kib: u32, parallelism: u32) -> Self {
        Self { iterations, memory_kib, parallelism }
    }
}

impl From<&WasmKdfParams> for KdfParams {
    fn from(p: &WasmKdfParams) -> Self {
        KdfParams { iterations: p.iterations, memory_kib: p.memory_kib, parallelism: p.parallelism }
    }
}

#[wasm_bindgen]
pub fn wasm_derive_auth_hash(password: &str, salt_str: &str, p: &WasmKdfParams) -> Result<String, JsError> {
    derive_auth_hash(password, salt_str, &p.into()).map_err(JsError::from)
}

#[wasm_bindgen]
pub fn wasm_derive_kek(password: &str, salt_b64: &str, p: &WasmKdfParams) -> Result<String, JsError> {
    derive_kek(password, salt_b64, &p.into()).map(|k| STANDARD.encode(&k)).map_err(JsError::from)
}

#[wasm_bindgen]
pub fn wasm_generate_vault_key() -> String {
    STANDARD.encode(&generate_vault_key().unwrap())
}

#[wasm_bindgen]
pub fn wasm_generate_salt() -> Result<String, JsError> {
    generate_salt().map_err(JsError::from)
}

#[wasm_bindgen]
pub fn wasm_wrap_vault_key(kek_b64: &str, vault_key_b64: &str) -> Result<String, JsError> {
    let kek = STANDARD.decode(kek_b64).map_err(|_| JsError::new("base64 decode failed"))?;
    let vk = STANDARD.decode(vault_key_b64).map_err(|_| JsError::new("base64 decode failed"))?;
    wrap_vault_key(&kek, &vk).map_err(JsError::from)
}

#[wasm_bindgen]
pub fn wasm_unwrap_vault_key(kek_b64: &str, wrapped_b64: &str) -> Result<String, JsError> {
    let kek = STANDARD.decode(kek_b64).map_err(|_| JsError::new("base64 decode failed"))?;
    unwrap_vault_key(&kek, wrapped_b64).map(|k| STANDARD.encode(&k)).map_err(JsError::from)
}

#[wasm_bindgen]
pub fn wasm_encrypt_entry(vault_key_b64: &str, plaintext_json: &str) -> Result<String, JsError> {
    let vk = STANDARD.decode(vault_key_b64).map_err(|_| JsError::new("base64 decode failed"))?;
    let ct = encrypt_entry(&vk, plaintext_json)?;
    serde_json::to_string(&ct).map_err(|e| JsError::new(&e.to_string()))
}

#[wasm_bindgen]
pub fn wasm_decrypt_entry(vault_key_b64: &str, encrypted_data: &str, iv: &str) -> Result<String, JsError> {
    let vk = STANDARD.decode(vault_key_b64).map_err(|_| JsError::new("base64 decode failed"))?;
    let ct = EntryCiphertext { encrypted_data: encrypted_data.to_string(), iv: iv.to_string() };
    decrypt_entry(&vk, &ct).map_err(JsError::from)
}

#[wasm_bindgen]
pub fn wasm_encrypt_field(vault_key_b64: &str, plaintext: &str) -> Result<String, JsError> {
    let vk = STANDARD.decode(vault_key_b64).map_err(|_| JsError::new("base64 decode failed"))?;
    encrypt_field(&vk, plaintext).map_err(JsError::from)
}

#[wasm_bindgen]
pub fn wasm_decrypt_field(vault_key_b64: &str, ciphertext: &str) -> Result<String, JsError> {
    let vk = STANDARD.decode(vault_key_b64).map_err(|_| JsError::new("base64 decode failed"))?;
    decrypt_field(&vk, ciphertext).map_err(JsError::from)
}



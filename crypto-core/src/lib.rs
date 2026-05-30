mod aead;
mod error;
mod kdf;
mod params;

#[cfg(target_arch = "wasm32")]
pub mod wasm;

#[cfg(target_os = "android")]
pub mod jni_bridge;

#[cfg(not(any(target_arch = "wasm32", target_os = "android")))]
pub mod c_ffi;

pub use error::CryptoError;
pub use params::{KdfParams, DEFAULT_PARAMS};

use aead::NONCE_LEN;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use zeroize::Zeroize;

const VERSION_PREFIX: &str = "v1:";
const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;

fn b64e(b: &[u8]) -> String {
    STANDARD.encode(b)
}

pub(crate) fn b64d(s: &str) -> Result<Vec<u8>, CryptoError> {
    STANDARD.decode(s).map_err(|_| CryptoError::Base64)
}

fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|_| CryptoError::Rng)?;
    Ok(buf)
}

// ---------------------------------------------------------------------------
// KDF
// ---------------------------------------------------------------------------

pub fn derive_auth_hash(password: &str, salt_str: &str, p: &KdfParams) -> Result<String, CryptoError> {
    let mut h = kdf::argon2id_raw(password.as_bytes(), salt_str.as_bytes(), p)?;
    let out = b64e(&h);
    h.zeroize();
    Ok(out)
}

pub fn derive_kek(password: &str, salt_b64: &str, p: &KdfParams) -> Result<Vec<u8>, CryptoError> {
    let mut salt = b64d(salt_b64)?;
    let h = kdf::argon2id_raw(password.as_bytes(), &salt, p);
    salt.zeroize();
    Ok(h?.to_vec())
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

pub fn generate_vault_key() -> Result<Vec<u8>, CryptoError> {
    Ok(random_bytes::<KEY_LEN>()?.to_vec())
}

pub fn generate_salt() -> Result<String, CryptoError> {
    Ok(b64e(&random_bytes::<SALT_LEN>()?))
}

// ---------------------------------------------------------------------------
// Envelope A — wrapped vault key: base64( nonce || ct||tag )
// ---------------------------------------------------------------------------

pub(crate) fn wrap_vault_key_with_nonce(
    kek: &[u8],
    vault_key: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<String, CryptoError> {
    let ct = aead::encrypt(kek, nonce, vault_key)?;
    let mut combined = Vec::with_capacity(NONCE_LEN + ct.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&ct);
    Ok(b64e(&combined))
}

pub fn wrap_vault_key(kek: &[u8], vault_key: &[u8]) -> Result<String, CryptoError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    wrap_vault_key_with_nonce(kek, vault_key, &nonce)
}

pub fn unwrap_vault_key(kek: &[u8], wrapped_b64: &str) -> Result<Vec<u8>, CryptoError> {
    let combined = b64d(wrapped_b64)?;
    if combined.len() <= NONCE_LEN {
        return Err(CryptoError::InvalidInput("wrapped key too short"));
    }
    let (nonce, ct) = combined.split_at(NONCE_LEN);
    aead::decrypt(kek, nonce, ct)
}

// ---------------------------------------------------------------------------
// Envelope B — entry: encrypted_data = "v1:"+b64(ct||tag), separate iv = b64(nonce)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct EntryCiphertext {
    #[serde(rename = "encryptedData")]
    pub encrypted_data: String,
    pub iv: String,
}

pub(crate) fn encrypt_entry_with_nonce(
    vault_key: &[u8],
    plaintext_json: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<EntryCiphertext, CryptoError> {
    let ct = aead::encrypt(vault_key, nonce, plaintext_json.as_bytes())?;
    Ok(EntryCiphertext {
        encrypted_data: format!("{VERSION_PREFIX}{}", b64e(&ct)),
        iv: b64e(nonce),
    })
}

pub fn encrypt_entry(vault_key: &[u8], plaintext_json: &str) -> Result<EntryCiphertext, CryptoError> {
    let nonce = random_bytes::<NONCE_LEN>()?;
    encrypt_entry_with_nonce(vault_key, plaintext_json, &nonce)
}

pub fn decrypt_entry(vault_key: &[u8], c: &EntryCiphertext) -> Result<String, CryptoError> {
    let raw = c.encrypted_data.strip_prefix(VERSION_PREFIX).unwrap_or(&c.encrypted_data);
    let ct = b64d(raw)?;
    let nonce = b64d(&c.iv)?;
    let pt = aead::decrypt(vault_key, &nonce, &ct)?;
    String::from_utf8(pt).map_err(|_| CryptoError::InvalidInput("plaintext not utf-8"))
}

// ---------------------------------------------------------------------------
// Envelope C — local field (Android cache parity): "v1:"+b64( nonce || ct||tag )
// ---------------------------------------------------------------------------

pub(crate) fn encrypt_field_with_nonce(
    vault_key: &[u8],
    plaintext: &str,
    nonce: &[u8; NONCE_LEN],
) -> Result<String, CryptoError> {
    let ct = aead::encrypt(vault_key, nonce, plaintext.as_bytes())?;
    let mut combined = Vec::with_capacity(NONCE_LEN + ct.len());
    combined.extend_from_slice(nonce);
    combined.extend_from_slice(&ct);
    Ok(format!("{VERSION_PREFIX}{}", b64e(&combined)))
}

pub fn encrypt_field(vault_key: &[u8], plaintext: &str) -> Result<String, CryptoError> {
    if plaintext.is_empty() {
        return Ok(String::new());
    }
    let nonce = random_bytes::<NONCE_LEN>()?;
    encrypt_field_with_nonce(vault_key, plaintext, &nonce)
}

pub fn decrypt_field(vault_key: &[u8], ciphertext: &str) -> Result<String, CryptoError> {
    if ciphertext.is_empty() {
        return Ok(String::new());
    }
    let raw = ciphertext.strip_prefix(VERSION_PREFIX).unwrap_or(ciphertext);
    let combined = b64d(raw)?;
    if combined.len() <= NONCE_LEN {
        return Err(CryptoError::InvalidInput("field ciphertext too short"));
    }
    let (nonce, ct) = combined.split_at(NONCE_LEN);
    let pt = aead::decrypt(vault_key, nonce, ct)?;
    String::from_utf8(pt).map_err(|_| CryptoError::InvalidInput("plaintext not utf-8"))
}

#[cfg(test)]
mod tests;
